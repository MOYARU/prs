```text
      :::::::::       :::::::::       :::::::: 
     :+:    :+:      :+:    :+:     :+:    :+: 
    +:+    +:+      +:+    +:+     +:+         
   +#++:++#+       +#++:++#:      +#++:++#++   
  +#+             +#+    +#+            +#+    
 #+#             #+#    #+#     #+#    #+#     
###             ###    ###      ########  
```
# PRS v1.6.0
### *Passive Reconnaissance Scanner*
### PRS focuses on risk visibility, not exploitation.

## Overview
PRS is a terminal-based web security scanner focused on identifying security misconfigurations, insecure defaults, 
and design-level risks.
It prioritizes clarity and safety over aggressive exploitation, providing actionable insights without attempting to compromise the target system.


## Design Philosophy
PRS is designed with the following 
```
principles:
1. Prefer passive analysis over active exploitation
2. Detect misconfigurations and insecure design patterns
3. Avoid intrusive or destructive behavior
4. Clearly communicate uncertainty and possible false positives
PRS does not attempt to exploit vulnerabilities.
Instead, it highlights conditions that may lead to security issues.
```

## Output Example
```
[HIGH] IDOR Possible
Numeric identifier changed: /resource/123 → /resource/124
Response behavior differed
Manual verification recommended
```

## Build
직접 빌드는 GO 환경이 필요합니다.
go build 와 본인의 운영체제를 선택하여 직접 빌드가 가능합니다.

EXE 파일을 설치했다면
해당 EXE 파일 위치를 터미널로 열어서
`.\PRS`
명령어로 실행이 가능합니다.

**prs (example.com) 으로 스캔합니다.**

#### 옵션 소개
```
1. --active : active모드를 이용합니다.
2. --depth : 크롤링 깊이를 설정합니다(기본값 : 2)
3. --json
4. --delay : 리퀘스트 사이에 딜레이를 넣습니다. 서버의 과부하를 방지합니다.
```

한글 / 영어 선택이 추가되었으며 방향키로 선택 가능합니다.

## roadmap
검사를 좀더 진득하게(?)