---
tags:
  - llm
  - deepseek
  - integration
---

# DeepSeek Integration

## Configuration
- API endpoint: `https://api.deepseek.com/v1/chat/completions`
- Model: `deepseek-chat`
- Max tokens: 1024, temperature: 0.7
- Timeout: 60 seconds

## API Key Resolution (`config.py`)
```
1. os.environ["DEEPSEEK_API_KEY"]  ← current shell
2. HKCU\Environment from registry  ← Windows UI (git-bash fallback)
3. ""                              ← not found → mock response
```

## Implementation (`agent.py:483-555`)
- Static method `ATPAgent.call_deepseek(prompt, monitor, conn_id)`
- Uses `aiohttp` client session
- Returns `None` on error, response text on success
- Monitors events: `DEEPSEEK_CALL_START`, `DEEPSEEK_CALL_END`

## Task Handler
Server-side: `_handle_task_request` → if `task_type == "deepseek_chat"`:
1. Sends TASK_ACK immediately
2. Calls DeepSeek API
3. Returns result in TASK_RESPONSE

Client-side: sends TASK_REQUEST with `task_type = "deepseek_chat"` and prompt in `task_payload`
