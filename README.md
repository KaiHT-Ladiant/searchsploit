# SearchSploit for Windows

Windows 네이티브 Python CLI로 [Exploit Database](https://www.exploit-db.com/)를 오프라인 검색합니다.

공식 bash `searchsploit`와 비슷한 옵션을 목표로 하며, [rad10/SearchSploit.py](https://github.com/rad10/SearchSploit.py)의 Windows 포팅 아이디어를 바탕으로 **현재 Exploit-DB CSV/GitLab 저장소**에 맞게 다시 작성했습니다.

> 이 도구는 Offensive Security / Exploit-DB의 공식 배포물이 아닙니다.  
> 로컬 DB는 [gitlab.com/exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb)를 clone 해서 사용합니다.

## 요구 사항

- Windows 10/11
- Python 3.9+
- Git (DB clone / `searchsploit -u`)
- 디스크: Exploit-DB 전체 clone은 **수 GB** 수준일 수 있음

## 빠른 설치

PowerShell (관리자 불필요):

```powershell
cd path\to\searchsploit
.\scripts\install.ps1 -ExploitDbPath C:\exploitdb -AddToPath
```

이미 DB가 있다면:

```powershell
.\scripts\install.ps1 -SkipClone -ExploitDbPath C:\exploitdb -AddToPath
```

수동 설치:

```powershell
pip install -e .
git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git C:\exploitdb
# %USERPROFILE%\.searchsploit_rc 의 path_array 를 C:/exploitdb 로 맞춤
```

## 사용 예

```text
searchsploit afd windows local
searchsploit -t oracle windows
searchsploit -p 39446
searchsploit -m 39446
searchsploit -x 39446
searchsploit -j afd windows
searchsploit --cve 2021-44228
searchsploit --nmap scan.xml
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
searchsploit -u
```

설정 파일 우선순위:

1. `%SEARCHSPLOIT_RC%` (환경 변수)
2. `%USERPROFILE%\.searchsploit_rc`
3. 패키지/실행 파일 옆 `.searchsploit_rc`

## 옵션 요약

| 옵션 | 설명 |
|------|------|
| `-c / --case` | 대소문자 구분 검색 |
| `-e / --exact` | 타이틀 정확 일치 (`-t` 포함) |
| `-s / --strict` | 버전 범위 fuzzy 매칭 비활성 |
| `-t / --title` | 타이틀만 검색 |
| `-j / --json` | JSON 출력 |
| `-m / --mirror` | 현재 폴더로 exploit 복사 |
| `-p / --path` | 전체 경로 출력 + 클립보드 복사 |
| `-x / --examine` | 로컬에서 파일 열기 |
| `-u / --update` | git pull 로 DB 갱신 |
| `-w / --www` | Exploit-DB URL 표시 |
| `--id` | 경로 대신 EDB-ID 표시 |
| `--cve` | CSV `codes` 컬럼 CVE 검색 |
| `--nmap` | Nmap XML / `-oG` 결과 검색 |
| `--exclude` | `\|` 로 제외어 연결 |
| `--colour` | 색상 하이라이트 끄기 |

## PyInstaller 단일 EXE

```powershell
pip install -e ".[dev]"
pyinstaller packaging\searchsploit.spec
```

결과물: `dist\searchsploit\searchsploit.exe`  
또는 `.\packaging\build.ps1` 로 portable zip을 만들 수 있습니다.  
EXE/zip은 검색 도구만 포함하며, Exploit-DB 본문은 `install.ps1`로 별도 clone 합니다.

## 라이선스

MIT. rad10/SearchSploit.py (MIT)에 영감을 받았으며, 공식 bash SearchSploit 스크립트를 복사하지 않은 독립 재구현입니다.  
Exploit-DB 데이터 자체는 해당 프로젝트 라이선스/정책을 따릅니다.

## 크레딧

- [Exploit Database / SearchSploit](https://www.exploit-db.com/searchsploit)
- [rad10/SearchSploit.py](https://github.com/rad10/SearchSploit.py)
