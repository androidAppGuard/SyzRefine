package fuzzer

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

const (

)

type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func CallDeepseekAPI(prompt_user string, messages []Message, llmurl string, llmmodel string, llmtoken string) string {
	// 1. create request
	request := ChatRequest{
		Model: llmmodel,
		// Model: "gpt-4o-mini-ca",
		// Model: "gpt-5-mini-ca",
		// Model: "gpt-5-nano-ca",
		// Model:    "gemini-2.5-flash-lite",
		Messages: []Message{},
	}
	if messages != nil || len(messages) > 0 {
		request.Messages = append(request.Messages, messages...)
	}
	request.Messages = append(request.Messages, Message{Role: "user", Content: prompt_user})

	// 2. Serialize request
	requestBody, err := json.Marshal(request)
	if err != nil {
		log.Logf(0, "Serialization request failed:%v", err)
		return ""
	}

	req, err := http.NewRequest("POST", llmurl, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Logf(0, "Create request failed: %v", err)
		return ""
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+llmtoken)
	req.Header.Set("max_tokens", "4096")

	//3. send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Logf(0, "Send request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	// 4. parse response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Logf(0, "Error response status code: %d, body: %s", resp.StatusCode, string(body))
		return ""
	}
	var response ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return ""
	}
	if len(response.Choices) == 0 || len(response.Choices[0].Message.Content) == 0 {
		return ""
	}
	if strings.Contains(response.Choices[0].Message.Content, "您的请求已被该站点的安全策略拦截") {
		panic("您的请求已被该站点的安全策略拦截\n")
	}
	return response.Choices[0].Message.Content
}

func extractTestcase(content string) string {
	re := regexp.MustCompile("(?s)```(.*?)```")
	testcase := ""
	matches := re.FindAllStringSubmatch(content, -1)
	if len(matches) != 0 {
		var codeBlocks []string
		for _, match := range matches {
			if len(match) > 1 {
				codeBlock := strings.TrimSpace(match[1])
				if codeBlock != "" {
					codeBlocks = append(codeBlocks, codeBlock)
				}
			}
		}
		if len(codeBlocks) == 0 {
			return testcase
		} else {
			for i := len(codeBlocks) - 1; i >= 0; i-- {
				if len(codeBlocks[i]) > 0 {
					testcase = codeBlocks[i] // Return the last code block
					break
				}
			}
		}
	}

	// basic syntax check
	lines := strings.Split(testcase, "\n")
	var filteredLines []string
	for _, line := range lines {
		if commentIndex := strings.Index(line, "// "); commentIndex != -1 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		if commentIndex := strings.Index(line, "# "); commentIndex != -1 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		if !strings.Contains(line, "(") || !strings.Contains(line, ")") {
			continue
		}
		line = strings.ReplaceAll(line, `='/`, `='./`)
		filteredLines = append(filteredLines, line)
	}
	testcase = strings.Join(filteredLines, "\n")
	return testcase
}

func extractCallSequence(content string, SyscallMap map[string]*prog.Syscall) []string {
	re := regexp.MustCompile("(?s)```(.*?)```")
	callSequence := []string{}
	matches := re.FindAllStringSubmatch(content, -1)
	match := ""
	if len(matches) != 0 {
		var codeBlocks []string
		for _, match := range matches {
			if len(match) > 1 {
				codeBlock := strings.TrimSpace(match[1])
				if codeBlock != "" {
					codeBlocks = append(codeBlocks, codeBlock)
				}
			}
		}
		if len(codeBlocks) > 0 {
			match = codeBlocks[len(codeBlocks)-1] // Return the last code block
		} else {
			return callSequence
		}
	}
	lines := strings.Split(match, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if commentIndex := strings.Index(line, "// "); commentIndex != -1 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		if commentIndex := strings.Index(line, "# "); commentIndex != -1 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		line = strings.ReplaceAll(line, " ", "")
		line = strings.ReplaceAll(line, "\n", "")
		if _, ok := SyscallMap[line]; ok && !SyscallMap[line].Attrs.Disabled && !SyscallMap[line].Attrs.NoGenerate {
			callSequence = append(callSequence, line)
		}
	}
	return callSequence
}
