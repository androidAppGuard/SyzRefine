package prog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/log"
)

type CallCount struct {
	CountofInvalid       int
	CountofValid         int
	CountofLLMGeneration int
}

type CallCorpus struct {
	validMu         sync.RWMutex
	invalidMu       sync.RWMutex
	crashMu         sync.RWMutex
	ValidProgsMap   map[string][]*Prog
	InvalidProgsMap map[string][]*Prog
	CrashProgsMap   map[string][]*Prog

	// CallExecuteCount[Name][0]: the number of valid call execution
	// CallExecuteCount[Name][1]: the number of invalid call execution
	// CallExecuteCount[Name][2]: the number of LLM generation
	callExecuteMu       sync.RWMutex
	CallExecuteCountMap map[string]*CallCount
}

func (callCorpus *CallCorpus) UpdateCallExecuteLLMGenerationCount(callName string) {
	callCorpus.callExecuteMu.Lock()
	defer callCorpus.callExecuteMu.Unlock()
	if _, ok := callCorpus.CallExecuteCountMap[callName]; !ok {
		callCorpus.CallExecuteCountMap[callName] = &CallCount{
			CountofInvalid:       0,
			CountofValid:         0,
			CountofLLMGeneration: 0,
		}
	}
	callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration++
}

func (callCorpus *CallCorpus) GetCallExecuteLLMGenerationCount(callName string) int {
	callCorpus.callExecuteMu.Lock()
	defer callCorpus.callExecuteMu.Unlock()
	if _, ok := callCorpus.CallExecuteCountMap[callName]; !ok {
		callCorpus.CallExecuteCountMap[callName] = &CallCount{
			CountofInvalid:       0,
			CountofValid:         0,
			CountofLLMGeneration: 0,
		}
	}
	return callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration
}

func (callCorpus *CallCorpus) UpdateCallExecuteCount(callName string, isValid bool) bool {
	callCorpus.callExecuteMu.Lock()
	defer callCorpus.callExecuteMu.Unlock()
	if _, ok := callCorpus.CallExecuteCountMap[callName]; !ok {
		callCorpus.CallExecuteCountMap[callName] = &CallCount{
			CountofInvalid:       0,
			CountofValid:         0,
			CountofLLMGeneration: 0,
		}
	}
	if isValid {
		callCorpus.CallExecuteCountMap[callName].CountofValid++
	} else {
		callCorpus.CallExecuteCountMap[callName].CountofInvalid++
	}

	// 1) this call has valid or the number of llmGeneration for this call over ThresholdMaxLLMGeneration
	if callCorpus.CallExecuteCountMap[callName].CountofValid > 0 || callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration > ThresholdMaxLLMGeneration {
		return false
	}
	// 2) this call has no valid execution
	if callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration == 0 {
		if callCorpus.CallExecuteCountMap[callName].CountofInvalid > ThresholdOfInvalidCount {
			callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration++
			return true
		}
	} else {
		requireThreshold := ThresholdOfInvalidCount + callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration*ThresholdOfIntervalCount
		if callCorpus.CallExecuteCountMap[callName].CountofInvalid > requireThreshold {
			callCorpus.CallExecuteCountMap[callName].CountofLLMGeneration++
			return true
		}
	}
	return false
}

func (callCorpus *CallCorpus) SaveValidProg(callName string, p *Prog) {
	callCorpus.validMu.Lock()
	defer callCorpus.validMu.Unlock()

	if callCorpus.ValidProgsMap[callName] != nil {
		callCorpus.ValidProgsMap[callName] = append(callCorpus.ValidProgsMap[callName], p)
	} else {
		callCorpus.ValidProgsMap[callName] = []*Prog{p}
	}
}
func (callCorpus *CallCorpus) GetValidProgs(callName string) []*Prog {
	callCorpus.validMu.RLock()
	defer callCorpus.validMu.RUnlock()

	_, ok := callCorpus.ValidProgsMap[callName]
	if !ok {
		return nil
	}
	return callCorpus.ValidProgsMap[callName]
}

func (callCorpus *CallCorpus) SaveInValidProg(callName string, p *Prog) {
	callCorpus.invalidMu.Lock()
	defer callCorpus.invalidMu.Unlock()

	if callCorpus.InvalidProgsMap[callName] != nil {
		callCorpus.InvalidProgsMap[callName] = append(callCorpus.InvalidProgsMap[callName], p)
	} else {
		callCorpus.InvalidProgsMap[callName] = []*Prog{p}
	}
}

func (callCorpus *CallCorpus) GetInValidProgs(callName string) []*Prog {
	callCorpus.invalidMu.RLock()
	defer callCorpus.invalidMu.RUnlock()

	_, ok := callCorpus.InvalidProgsMap[callName]
	if !ok {
		return nil
	}
	return callCorpus.InvalidProgsMap[callName]
}

func (callCorpus *CallCorpus) LoadCrashProgs(crashDir string, target *Target) {
	files, err := os.ReadDir(crashDir)
	if err != nil {
		panic("wrong crashDir\n")
	}
	crashProgCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		filePath := filepath.Join(crashDir, file.Name())
		content, err := os.ReadFile(filePath)

		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file.Name(), err)
			continue
		}
		crashProg, err := target.Deserialize(content, NonStrict)
		if err == nil {
			needLoad := true
			for _, call := range crashProg.Calls {
				if call.Meta.Attrs.Disabled || call.Meta.Attrs.NoGenerate {
					needLoad = false
				}
			}
			if needLoad {
				call := crashProg.Calls[len(crashProg.Calls)-1]
				callCorpus.SaveCrashProg(call.Meta.Name, crashProg)
				crashProgCount++
			}
		}
	}
	log.Logf(0, "crashProgCount:%v, call count:%v\n", crashProgCount, len(callCorpus.CrashProgsMap))
}

func (callCorpus *CallCorpus) GetCrashProgs(callName string) []*Prog {
	callCorpus.crashMu.RLock()
	defer callCorpus.crashMu.RUnlock()

	_, ok := callCorpus.CrashProgsMap[callName]
	if !ok {
		return nil
	}
	return callCorpus.CrashProgsMap[callName]
}

func (callCorpus *CallCorpus) SaveCrashProg(callName string, p *Prog) {
	callCorpus.crashMu.Lock()
	defer callCorpus.crashMu.Unlock()

	if callCorpus.CrashProgsMap[callName] != nil {
		callCorpus.CrashProgsMap[callName] = append(callCorpus.CrashProgsMap[callName], p)
	} else {
		callCorpus.CrashProgsMap[callName] = []*Prog{p}
	}
}
