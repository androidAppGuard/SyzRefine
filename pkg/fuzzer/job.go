// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// var TestFlag bool = false

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable())
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	return job.fuzzer.executeWithFlags(job.queue, req, flags)
}

// Annotation: each Job has run method, is called by /data/ghui/phd2/experiment_code/syzkaller_new/pkg/fuzzer/fuzzer.go
// Annotation: func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job)
func (job *triageJob) run(fuzzer *Fuzzer) {
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info)
			wg.Done()
		}()
	}
	wg.Wait()
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() {
		return
	}

	p := job.p.Clone()
	if job.flags&ProgMinimized == 0 { //&& job.flags&ProgFromCorpus != 1 avoid repeated minimization for different initial corpus
		p, call = job.minimize(call, info)
		if p == nil {
			return
		}
	}

	// Instrumentation
	if job.flags&ProgFromCorpus == 1 || job.flags&ProgMinimized == 0 {
		if call != -1 && p.Calls[call].Errno == 0 {
			callName := p.Calls[call].Meta.Name
			p.Target.CallCorpus.SaveValidProg(callName, p.Clone())
		}
		if call != -1 && p.Calls[call].Errno != 0 {
			callName := p.Calls[call].Meta.Name
			p.Target.CallCorpus.SaveInValidProg(callName, p.Clone())
		}
	}

	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec: job.fuzzer.smashQueue,
			p:    p.Clone(),
			info: &JobInfo{
				Name:  p.String(),
				Type:  "smash",
				Calls: []string{p.CallName(call)},
			},
		})
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:  p.String(),
					Type:  "hints",
					Calls: []string{p.CallName(call)},
				},
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
			})
		}
	}

	if call != -1 { //  invalid interesting context
		interestingProg := p.Clone()
		for i := len(interestingProg.Calls) - 1; i > call; i-- {
			interestingProg.RemoveCall(i)
		}
		if p.Calls[call].Errno != 0 {
			if _, ok := p.Target.PriorityQueue[interestingProg.Calls[call].Meta.ID]; !ok {
				log.Logf(0, "impossible case, call Id of interestingInvalidProg not in PriorityQueue\n")
			} else {
				p.Target.PriorityQueue[interestingProg.Calls[call].Meta.ID].AddInterestingInvalidProg(interestingProg)
				p.Target.AddGlobalInterestingInvalidCount()
			}
		} else { // valid interesting context
			if _, ok := p.Target.PriorityQueue[p.Calls[call].Meta.ID]; !ok {
				log.Logf(0, "impossible case, call Id (%v) of interestingValidProg not in PriorityQueue\n", p.Calls[call].Meta.Name)
			} else {
				p.Target.PriorityQueue[p.Calls[call].Meta.ID].AddInterestingValidCount()
				p.Target.AddGlobalInterestingValidCount()
			}
		}

	}

	job.fuzzer.statNewInputs.Add(1)
	if p.Progtype == ProgtypeLLM {
		job.fuzzer.statRecordNewInputsLLMtype.Add(1)
	}

	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		if result.Stop() {
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
	}
	return false
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) minimize(call int, info *triageCall) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		for i := 0; i < minimizeAttempts; i++ {
			result := job.execute(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, 0)
			if result.Stop() {
				stop = true
				return false
			}
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	// // test specification
	// if !TestFlag {
	// 	TestFlag = true
	// 	fuzzer.Logf(0, "enter TestSpecification function\n")
	// 	programs := prog.TestSpecification(fuzzer.rand(), fuzzer.target, fuzzer.Config.EnabledCalls, fuzzer.ChoiceTable())
	// 	fuzzer.Logf(0, "length of programs:%v\n", len(programs))
	// 	for _, p := range programs {
	// 		fuzzer.execute(job.exec, &queue.Request{
	// 			Prog:     p,
	// 			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
	// 			Stat:     fuzzer.statTestSpecification,
	// 		})
	// 	}
	// 	fuzzer.Logf(0, "executing finish\n")

	// }
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	// iters := 25 * errnoCount / len(job.p.Errnos)
	const iters = 25
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
	}

}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	// Annotation: execute 3 times to collect the comparision operator
	var comps prog.CompMap
	for i := 0; i < 3; i++ {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}

// Consume Code
func repairCallWithLLM(p *prog.Prog, call *prog.Call, fuzzer *Fuzzer, logRecord *prog.LogRecord) (bool, *prog.Prog) {
	if call == nil {
		return false, nil
	}
	if call.Meta.Attrs.Disabled || call.Meta.Attrs.NoGenerate {
		return false, nil
	}

	// 1) remove the calls after call
	target_index := -1
	for index, c := range p.Calls {
		if c == call {
			target_index = index
			break
		}
	}
	// analyze/record result arg relation
	p_record := p.Clone()
	argCallMap := make(map[*prog.ResultArg]*prog.Call)
	for i := 0; i <= target_index; i++ {
		prog.ForeachArg(p_record.Calls[i], func(arg prog.Arg, ctx *prog.ArgCtx) {
			if resultArg, ok := arg.(*prog.ResultArg); ok {
				argCallMap[resultArg] = p_record.Calls[i]
			}
		})
	}
	analyzeResult := make(map[*prog.Call]string)
	for i := target_index + 1; i < len(p_record.Calls); i++ {
		analyzeCall := p_record.Calls[i]
		prog.ForeachArg(analyzeCall, func(arg prog.Arg, ctx *prog.ArgCtx) {
			if resultArg, ok_resultArg := arg.(*prog.ResultArg); ok_resultArg && resultArg.Res != nil {
				if resCall, ok_res := argCallMap[resultArg.Res]; ok_res { //ref previous args
					key := analyzeCall
					value := resultArg.Type().Name() + "->" + resCall.Meta.Name + "->" + resultArg.Res.Type().Name()
					analyzeResult[key] = value
				}
			}
		})
	}
	for i := target_index; i >= 0; i-- {
		p_record.RemoveCall(i)
	}
	for i := len(p.Calls) - 1; i > target_index; i-- {
		p.RemoveCall(i)
	}

	// 2) generate prompt
	pro_content_src := string(p.Serialize_consume())
	callName := call.Meta.Name
	errorno := call.Errno
	errorDefine := ""
	errorContent := ""
	if description, ok := prog.ErrornoDescriptionMap[errorno]; ok {
		errorDefine = description[0]
		errorContent = description[1]
	}
	logRecord.LogContent += fmt.Sprintf("(1) Extracted Program:\n%s\n", pro_content_src)

	prompt_instructionStep := fmt.Sprintf(prog.PromptRepairInstructionAndStepsTemplate,
		callName, errorDefine, errorno, errorContent,
		callName, callName,
		callName,
		callName,
		callName,
	)

	prompt_input := fmt.Sprintf("# Inputs\n## 1. Faulty Syz Program\n%s\n", pro_content_src)

	execution_info := "## 2. Execution Results\n"
	for _, c := range p.Calls {
		cErrorNo := c.Errno
		cErrorDefine := ""
		cErrorContent := ""
		if description, ok := prog.ErrornoDescriptionMap[cErrorNo]; ok {
			cErrorDefine = description[0]
			cErrorContent = description[1]
		}
		execution_info += fmt.Sprintf("%s: %s(%v), which represents %s\n", c.Meta.Name, cErrorDefine, cErrorNo, cErrorContent)
	}
	prompt_input += execution_info + "\n"

	description := "## 3. Syzlang Specification\n"
	for _, c := range p.Calls {
		specification := c.Meta.GenerateSyzlangSpecs()
		description += specification + "\n"
	}
	prompt_input += description + "\n"

	success_program := fmt.Sprintf("## 4. Previously Successful %s Examples (it can trigger new code coverage)\n", callName)
	successful_programs := fuzzer.target.CallCorpus.GetValidProgs(callName)
	if successful_programs == nil {
		success_program += fmt.Sprintf("There is no Syz program from previously successful execution for %s.\n\n", callName)
	} else { // Select up to three successful program
		index := fuzzer.rnd.Intn(len(successful_programs))
		success_program += fmt.Sprintf("%s\n", successful_programs[index].Serialize_consume())
	}
	prompt_input += success_program

	syntaxProgram_content := "## 5. Syntactically Correct Programs (Reference for Target)\n"
	candidatePrograms := []*prog.Prog{}
	for range 10 {
		candidateProgram := fuzzer.target.GenerateProgByMeta(call.Meta, fuzzer.ct)
		if len((candidateProgram.Calls)) == 0 {
			continue
		}
		candidatePrograms = append(candidatePrograms, candidateProgram)
	}
	sort.Slice(candidatePrograms, func(i, j int) bool {
		return len(candidatePrograms[i].Calls) > len(candidatePrograms[j].Calls)
	})
	syntaxPrograms := []*prog.Prog{}
	for _, syntaxProgram := range candidatePrograms {
		syntaxProgram.Mutate(rand.New(rand.NewSource(rand.Int63())), prog.RecommendedCalls, fuzzer.ct, fuzzer.Config.NoMutateCalls, fuzzer.Config.Corpus.Programs())
		if syntaxProgram.FindCallByName(callName) == -1 {
			continue
		}
		syntaxPrograms = append(syntaxPrograms, syntaxProgram)
		if len(syntaxPrograms) >= 1 {
			break
		}
	}
	if prog.Config_PocModel {
		programCount := 1
		progs := fuzzer.target.CallCorpus.GetCrashProgs(callName)
		if progs != nil {
			if len(progs) >= 3 {
				for programCount < 4 {
					prog := progs[rand.Intn(len(progs))]
					syntaxProgram_content += fmt.Sprintf("Program %v\n%s\n", programCount, prog.Serialize())
					programCount++
				}
			} else {
				for programCount < len(progs) {
					prog := progs[programCount-1]
					syntaxProgram_content += fmt.Sprintf("Program %v\n%s\n", programCount, prog.Serialize())
					programCount++

				}
			}
		}
		for programCount < 4 {
			syntaxProgram_content += fmt.Sprintf("Program %v\n%s\n", programCount, syntaxPrograms[programCount-1].Serialize())
			programCount++
		}
	} else {
		for i := range len(syntaxPrograms) {
			syntaxProgram_content += fmt.Sprintf("%s\n", syntaxPrograms[i].Serialize_consume())
		}

	}
	prompt_input += syntaxProgram_content

	prompt_output := fmt.Sprintf(prog.PromptRepairOutputTemplate)

	prompt := prompt_instructionStep + prompt_input + prompt_output
	if len(prompt) > 50000 {
		return false, nil
	}
	logRecord.LogContent += fmt.Sprintf("(2) Generated Prompt:\n%s\n\n", prompt)

	// 3) call llm model
	messages := []Message{
		// {Role: "system", Content: prompt_system},
	}
	fuzzer.statRecordLLMFix.Add(1)
	responseBody := CallDeepseekAPI(prompt, messages, fuzzer.target.LLMURL, fuzzer.target.LLMMODE, fuzzer.target.LLMTOKEN)
	testcase := extractTestcase(responseBody)
	if len(testcase) <= 0 {
		logRecord.LogContent += fmt.Sprintf("(3) LLM Repair Response:\n%s\n********************************************************\n\n", responseBody)
		return false, nil
	}
	logRecord.LogContent += fmt.Sprintf("(3) LLM Repair Response:\n%s\n\n", responseBody)
	p_fix, err := fuzzer.target.Deserialize([]byte(testcase), prog.NonStrict)
	// messages_retry := []Message{
	// 	// {Role: "system", Content: prompt_system},
	// 	{Role: "user", Content: prompt},
	// 	{Role: "assistant", Content: responseBody},
	// }
	// retry_count := 0
	// for err != nil && retry_count < 1 {
	// 	retry_count++
	// 	prompt_retry := fmt.Sprintf("The fixed syz program has syntax error:%v\nPlease refix it and output the fixed syz program. Note that the syz program must be wrapped with ```, like this:\n```\nthe fixed syz program\n```\n", err)
	// 	responseBody = CallDeepseekAPI(prompt_retry, messages_retry)
	// 	testcase := extractTestcase(responseBody)
	// 	if len(testcase) <= 0 {
	// 		logRecord.LogContent += fmt.Sprintf("LLM Repair API Retry Failed:%s\n%s\n", prompt_retry, responseBody)
	// 		continue
	// 	}
	// 	p_fix, err = fuzzer.target.Deserialize([]byte(testcase), prog.NonStrict)
	// 	messages_retry = append(messages_retry, []Message{{Role: "user", Content: prompt_retry}, {Role: "assistant", Content: responseBody}}...)
	// }

	if err != nil {
		logRecord.LogContent += fmt.Sprintf("(4) LLM Repair Failed as syntax error:%s\n Fixed test case:\n%s\n********************************************************\n\n", err, testcase)
		if len(syntaxPrograms) != 0 {
			for _, syntaxProgram := range syntaxPrograms {
				syntaxProgram.Progtype = ProgtypeLLM
				go func() {
					fuzzer.execute(fuzzer.smashQueue, &queue.Request{
						Prog:     syntaxProgram,
						ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
						Stat:     fuzzer.statExecSmash,
					})
				}()
			}
		}
		return false, nil
	}
	logRecord.LogContent += fmt.Sprintf("(4) LLM Repair Synatx Success: fixed test case:\n%s\n\n", testcase)

	// append p_record
	for referCall, referInfo := range analyzeResult {
		infos := strings.Split(referInfo, "->")
		referTypeName := infos[0]
		candidateMetaName := infos[1]
		candidateTypeName := infos[2]
		for i := len(p_fix.Calls) - 1; i >= 0; i-- {
			is_stop := false
			candidateCall := p_fix.Calls[i]
			if candidateCall.Meta.Name != candidateMetaName {
				continue
			}
			prog.ForeachArg(candidateCall, func(candidateArg prog.Arg, candidateCtx *prog.ArgCtx) {
				if candidateResultArg, ok_candidate := candidateArg.(*prog.ResultArg); ok_candidate && candidateResultArg.Type().Name() == candidateTypeName && candidateCtx.Field == nil {
					prog.ForeachArg(referCall, func(referArg prog.Arg, referCtx *prog.ArgCtx) {
						if referResultArg, ok_refer := referArg.(*prog.ResultArg); ok_refer && referResultArg.Type().Name() == referTypeName && referCtx.Field != nil {
							is_stop = true
							referResultArg.Res = candidateResultArg
							candidateResultArg.InsertUse(referResultArg)
							log.Logf(0, "has finding\n")
						}
					})

				}
			})

			if is_stop {
				break
			}
		}

	}
	p_fix.Calls = append(p_fix.Calls, p_record.Calls...)
	logRecord.LogContent += fmt.Sprintf("(5) Merged program:\n%s\n\n", p_fix.Serialize_consume())

	// 4) execute
	ids := []int{}
	isNeedUpdate := false
	for index, call := range p_fix.Calls {
		needDelete := false
		if call.Meta.Attrs.Disabled || call.Meta.Attrs.NoGenerate {
			needDelete = true
		}
		if !fuzzer.ct.Generatable(call.Meta.ID) {
			fuzzer.Config.EnabledCalls[call.Meta] = true
			isNeedUpdate = true
		}
		if needDelete {
			ids = append(ids, index)
		}
	}
	for i := len(ids) - 1; i >= 0; i-- {
		p_fix.RemoveCall(ids[i])
	}
	if isNeedUpdate {
		fuzzer.updateChoiceTable(append(fuzzer.Config.Corpus.Programs(), p_fix))
	}
	if len(p_fix.Calls) <= 0 {
		log.Logf(0, "len(p_fix.Calls) <= 0 ")
		return false, nil
	}
	for len(p_fix.Calls) > prog.RecommendedCalls {
		p_fix.RemoveCall(len(p_fix.Calls) - 1)
	}

	repairCallIndex := p_fix.FindCallByName(call.Meta.Name)
	p_fix.Progtype = ProgtypeLLM
	new_req := &queue.Request{
		Prog:               p_fix.Clone(),
		ExecOpts:           setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:               fuzzer.statRecordLLMFixGrammar,
		OperationType:      LLMRepairModel,
		OperationCallIndex: repairCallIndex,
		Prompt:             prompt,
	}
	result := fuzzer.execute(fuzzer.candidateQueue, new_req)
	if repairCallIndex == -1 || result == nil || result.Info == nil || result.Info.Calls == nil {
		return false, nil
	}
	errno_description := ""
	resultErrnoDescription := ""
	if _, ok := prog.ErrornoDescriptionMap[errorno]; ok {
		errno_description = prog.ErrornoDescriptionMap[errorno][1]
	}
	if _, ok := prog.ErrornoDescriptionMap[result.Info.Calls[repairCallIndex].Error]; ok {
		resultErrnoDescription = prog.ErrornoDescriptionMap[result.Info.Calls[repairCallIndex].Error][1]
	}

	for i, c := range result.Info.Calls {
		if i > repairCallIndex {
			continue
		}
		if c.Error == 0 {
			fuzzer.statRecordRepairExecutionValid.Add(1)
		}
		fuzzer.statRecordRepairExecutionTotal.Add(1)
	}

	if result.Info.Calls[repairCallIndex].Error != 0 {
		logRecord.LogContent += fmt.Sprintf("(6) Repair Program %s Execution Failed (errno:%v(%s)->%v(%s))\n********************************************************\n\n", call.Meta.Name, errorno, errno_description, result.Info.Calls[repairCallIndex].Error, resultErrnoDescription)
		return false, nil
	} else {

		logRecord.LogContent += fmt.Sprintf("(6) LLM Repair %s Execution Success (errno:%v(%s))\n********************************************************\n\n", call.Meta.Name, errorno, resultErrnoDescription)
		return true, p_fix
	}
}

func RepairCallOperator(p *prog.Prog, callIndex int, fuzzer *Fuzzer) {
	go func() {
		prog.RepairSem <- struct{}{}
		defer func() { <-prog.RepairSem }()

		p = p.Clone()
		p_original := p.Clone()
		logRecord := &prog.LogRecord{
			LogContent: "",
		}
		logRecord.LogContent += fmt.Sprintf("=============Begain Repair Seed program=============\n%s\n", p_original.Serialize())
		for index, originalCall := range p_original.Calls {
			if index > callIndex {
				break
			}
			if originalCall.Errno == 0 {
				continue
			}
			p_candidate_llm := p.Clone()
			repairCall := p_candidate_llm.FindCallByNameError(originalCall)
			if repairCall == nil {
				continue
			}
			logRecord.LogContent += fmt.Sprintf("##### Now repair call %v(%s)\n", index, originalCall.Meta.Name)
			llm_result, p_fix := repairCallWithLLM(p_candidate_llm, repairCall, fuzzer, logRecord)
			if llm_result {
				p = p_fix
			}
		}
		logRecord.LogContent += "=============End Repair Seed Program=============\n"
		log.Logf(0, "%s\n", logRecord.LogContent)
	}()
}

func GenerationCallOperator(metaCall *prog.Syscall, fuzzer *Fuzzer) {
	if metaCall.Attrs.Disabled || metaCall.Attrs.NoGenerate {
		return
	}

	go func() {
		prog.GenerationSem <- struct{}{}
		defer func() { <-prog.GenerationSem }()
		logRecord := &prog.LogRecord{
			LogContent: "",
		}
		logRecord.LogContent += fmt.Sprintf("=============Begin generate program for %s=============\n", metaCall.Name)
		targetCallName := metaCall.Name
		relatedSyscalls := fuzzer.ct.ChooseRelatedCalls(fuzzer.rand(), metaCall.ID, 10)

		// 1) generate template
		template_result := []string{}
		if len(relatedSyscalls) == 0 {
			template_result = append(template_result, targetCallName)
		} else {
			prompt_template_instruction := fmt.Sprintf(prog.PromptGenerationRelatedCallInstruction, targetCallName, targetCallName, targetCallName)

			prompt_template_input := fmt.Sprintf("# Inputs\n## 1. Target System Call\n%s\n\n## 2. Candidate System Calls List", targetCallName)
			for _, relatedSyscall := range relatedSyscalls {
				prompt_template_input += relatedSyscall.Name + "\n"
			}
			prompt_template_input += "\n"
			prompt_template_output := "# Output Requirements\nConstruct the final system call sequence. Output **ONLY** the sequence in the following format:\n```\nsystem call1\nsystem call2\n...\n```\n"
			prompt_template := prompt_template_instruction + prompt_template_input + prompt_template_output
			logRecord.LogContent += fmt.Sprintf("(1) Template prompt\n%s\n", prompt_template)
			// 1.1) call llm
			messages := []Message{
				// {Role: "system", Content: prompt_system},
			}
			responseBody := CallDeepseekAPI(prompt_template, messages, fuzzer.target.LLMURL, fuzzer.target.LLMMODE, fuzzer.target.LLMTOKEN)

			template_result = extractCallSequence(responseBody, fuzzer.target.SyscallMap)
			if len(template_result) <= 0 {
				template_result = append(template_result, targetCallName)
				logRecord.LogContent += fmt.Sprintf("(1.1) Template no response:\n%s\n", responseBody)
			} else {
				logRecord.LogContent += fmt.Sprintf("(1.1) Template sequence:\n%s\nResponse:\n%s\n", template_result, responseBody)
			}
		}

		// 2) Instantiate the call sequence
		generatePrograms := []string{}
		for targetIndex, generateCallName := range template_result {
			generateCallMeta := fuzzer.target.SyscallMap[generateCallName]
			prompt_generate_instructionStep := ""
			generated_callNames := ""
			if len(generatePrograms) == 0 {
				prompt_generate_instructionStep = fmt.Sprintf(prog.PromptGenerationInitInstructionSteps_NoSpecific,
					generateCallName, generateCallName, generateCallName, generateCallName)
			} else {
				for i := range targetIndex {
					if i != targetIndex-1 {
						generated_callNames += template_result[i] + ","
					} else {
						generated_callNames += template_result[i]
					}
				}
				prompt_generate_instructionStep = fmt.Sprintf(prog.PromptGenerationInitInstructionSteps_HasSpecific,
					generateCallName, generated_callNames, generated_callNames, generateCallName, generateCallName, generateCallName)
			}
			prompt_generate_instructionStep += "\n"

			template_call_sequence := ""
			for i := 0; i <= targetIndex; i++ {
				template_call_sequence += template_result[i] + "\n"
			}
			prompt_generate_input := fmt.Sprintf("# Inputs\n## Target System Call Sequence Template\n%s\n", template_call_sequence)
			if len(generatePrograms) != 0 {
				prompt_generate_input += fmt.Sprintf("## Reference: Specified Programs for %s\n", generated_callNames)
				for i := range len(generatePrograms) {
					prompt_generate_input += fmt.Sprintf("- The program for context extraction of %s.\n%s\n", template_result[i], generatePrograms[i])
				}
			}

			prompt_generate_input += fmt.Sprintf("## System call description of  %s**\n%s\n\n", generateCallName, generateCallMeta.GenerateSyzlangSpecs())
			prompt_generate_input += "## Syntactically Correct Programs (Reference for Target)\n"

			candidatePrograms := []*prog.Prog{}
			for range 10 {
				candidateProgram := fuzzer.target.GenerateProgByMeta(generateCallMeta, fuzzer.ct)
				if len((candidateProgram.Calls)) == 0 {
					continue
				}
				candidatePrograms = append(candidatePrograms, candidateProgram)
			}
			sort.Slice(candidatePrograms, func(i, j int) bool {
				return len(candidatePrograms[i].Calls) > len(candidatePrograms[j].Calls)
			})
			syntaxPrograms := []*prog.Prog{}
			for _, syntaxProgram := range candidatePrograms {
				syntaxProgram.Mutate(rand.New(rand.NewSource(rand.Int63())), prog.RecommendedCalls, fuzzer.ct, fuzzer.Config.NoMutateCalls, fuzzer.Config.Corpus.Programs())
				if syntaxProgram.FindCallByName(generateCallName) == -1 {
					continue
				}
				syntaxPrograms = append(syntaxPrograms, syntaxProgram)
				if len(syntaxPrograms) >= 1 {
					break
				}
			}
			if prog.Config_PocModel {
				programCount := 1
				progs := fuzzer.target.CallCorpus.GetCrashProgs(generateCallName)
				if progs != nil {
					if len(progs) >= 3 {
						for programCount < 4 {
							prog := progs[rand.Intn(len(progs))]
							prompt_generate_input += fmt.Sprintf("Program %v\n%s\n", programCount, prog.Serialize())
							programCount++
						}
					} else {
						for programCount < len(progs) {
							prog := progs[programCount-1]
							prompt_generate_input += fmt.Sprintf("Program %v\n%s\n", programCount, prog.Serialize())
							programCount++

						}
					}
				}
				for programCount < 4 {
					prompt_generate_input += fmt.Sprintf("Program %v\n%s\n", programCount, syntaxPrograms[programCount-1].Serialize())
					programCount++
				}
			} else {
				for i := range len(syntaxPrograms) {
					prompt_generate_input += fmt.Sprintf("%s\n", syntaxPrograms[i].Serialize_consume())
				}
			}

			prompt_generate_output := prog.PromptGenerationInitOutput
			prompt_generate := prompt_generate_instructionStep + prompt_generate_input + prompt_generate_output
			if len(prompt_generate) > 50000 {
				p_example := fuzzer.target.GenerateProgByMeta(fuzzer.target.SyscallMap[generateCallName], fuzzer.ct)
				generatePrograms = append(generatePrograms, string(p_example.Serialize_consume()))
				logRecord.LogContent += fmt.Sprintf("(2.1) Generate Skip as prompt size overlarge: %s\n", prompt_generate)
				continue
			}
			logRecord.LogContent += fmt.Sprintf("(2) Generate prompt for call%v (%s)\n%s\n", targetIndex, generateCallName, prompt_generate)

			// 2.1) call llm
			messages := []Message{
				// {Role: "system", Content: prompt_system},
			}
			fuzzer.statRecordLLMGeneration.Add(1)
			responseBody := CallDeepseekAPI(prompt_generate, messages, fuzzer.target.LLMURL, fuzzer.target.LLMMODE, fuzzer.target.LLMTOKEN)
			testcase := extractTestcase(responseBody)
			if len(testcase) <= 0 {
				p_example := fuzzer.target.GenerateProgByMeta(fuzzer.target.SyscallMap[generateCallName], fuzzer.ct)
				generatePrograms = append(generatePrograms, string(p_example.Serialize_consume()))
				logRecord.LogContent += fmt.Sprintf("(2.1) Generate No Response: %s\n", responseBody)
				continue
			}
			logRecord.LogContent += fmt.Sprintf("(2.1) Generate Response:\n%s\n", responseBody)
			p_generate, err := fuzzer.target.Deserialize([]byte(testcase), prog.NonStrict)
			if err != nil {
				p_example := fuzzer.target.GenerateProgByMeta(fuzzer.target.SyscallMap[generateCallName], fuzzer.ct)
				logRecord.LogContent += fmt.Sprintf("(2.2) Generate syntax failed: %s\nGenerated program:\n%s\n", err, testcase)
				generatePrograms = append(generatePrograms, string(p_example.Serialize_consume()))
				if len(syntaxPrograms) != 0 {
					for _, syntaxProgram := range syntaxPrograms {
						go func() {
							syntaxProgram.Progtype = ProgtypeLLM
							fuzzer.execute(fuzzer.smashQueue, &queue.Request{
								Prog:     syntaxProgram,
								ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
								Stat:     fuzzer.statExecSmash,
							})
						}()
					}
				}
			} else {
				logRecord.LogContent += fmt.Sprintf("(2.2) Generate syntax success: generated program:\n%s\n", testcase)
				generatePrograms = append(generatePrograms, string(p_generate.Serialize_consume()))

				ids := []int{}
				isNeedUpdate := false
				for index, call := range p_generate.Calls {
					needDelete := false
					if call.Meta.Attrs.Disabled || call.Meta.Attrs.NoGenerate {
						needDelete = true
					}
					if !fuzzer.ct.Generatable(call.Meta.ID) {
						fuzzer.Config.EnabledCalls[call.Meta] = true
						isNeedUpdate = true
					}
					if needDelete {
						ids = append(ids, index)
					}
				}
				for i := len(ids) - 1; i >= 0; i-- {
					p_generate.RemoveCall(ids[i])
				}
				if isNeedUpdate {
					fuzzer.updateChoiceTable(append(fuzzer.Config.Corpus.Programs(), p_generate))
				}
				if len(p_generate.Calls) <= 0 {
					log.Logf(0, "len(p_generate.Calls) <= 0 ")
					continue
				}

				for len(p_generate.Calls) > prog.RecommendedCalls {
					p_generate.RemoveCall(len(p_generate.Calls) - 1)
				}

				generateCallIndex := p_generate.FindCallByName(generateCallName)
				p_generate.Progtype = ProgtypeLLM
				new_req := &queue.Request{
					Prog:               p_generate.Clone(),
					ExecOpts:           setFlags(flatrpc.ExecFlagCollectSignal),
					Stat:               fuzzer.statRecordLLMGenerationGrammar,
					OperationType:      LLMGenerateModel,
					OperationCallIndex: generateCallIndex,
					Prompt:             prompt_generate,
				}
				result := fuzzer.execute(fuzzer.candidateQueue, new_req)
				if generateCallIndex == -1 || result == nil || result.Info == nil || result.Info.Calls == nil {
					continue
				}

				for _, c := range result.Info.Calls {
					if c.Error == 0 {
						fuzzer.statRecordGenerationExecutionValid.Add(1)
					}
					fuzzer.statRecordGenerationExecutionTotal.Add(1)
				}

				if result.Info.Calls[generateCallIndex].Error != 0 {
					logRecord.LogContent += fmt.Sprintf("(2.3) Generate execute failed:%s(%v)\n", generateCallName, result.Info.Calls[generateCallIndex].Error)
				} else {
					logRecord.LogContent += fmt.Sprintf("(2.3) Generate execute success:%s\n", generateCallName)
				}
			}
		}
		log.Logf(0, "%s\n=============End=============\n", logRecord.LogContent)
	}()
}
