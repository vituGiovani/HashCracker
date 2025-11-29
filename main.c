#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "md5.h" 

#pragma comment(lib, "comctl32.lib")

// --- CORES VISUAIS ---
#define COLOR_BG RGB(12, 12, 12)          
#define COLOR_TEXT RGB(0, 255, 100)        
#define COLOR_INPUT RGB(35, 35, 35)

// IDs
#define ID_BTN_GERAR    101
#define ID_BTN_SCAN     102
#define ID_BTN_ATACAR   103
#define ID_INPUT_SENHA  104
#define ID_INPUT_HASH   105
#define ID_CONSOLE      106
#define ID_PROGRESS     107

HWND hConsole, hProgress, hBtnAtacar, hInputSenha, hInputHash;
int g_NumCores = 1;
volatile BOOL g_Encontrada = FALSE; // Controle para parar threads

// Memória da Wordlist
char* g_KnowledgeBase = NULL;
long long g_TotalSize = 0;

// Logger
void LogConsole(const char* texto) {
    int len = GetWindowTextLength(hConsole);
    SendMessage(hConsole, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(hConsole, EM_REPLACESEL, 0, (LPARAM)texto);
    SendMessage(hConsole, EM_REPLACESEL, 0, (LPARAM)"\r\n");
}

// --- FUNÇÕES AUXILIARES ---

void HexToBinary(const char* hexString, unsigned char* output) {
    for (int i = 0; i < 16; i++) {
        sscanf(&hexString[i * 2], "%2hhx", &output[i]);
    }
}

void ApplyLeetSpeak(char* dest, const char* src) {
    int i = 0;
    while (src[i] != '\0') {
        char c = src[i];
        switch (c) {
        case 'a': case 'A': dest[i] = '4'; break;
        case 'e': case 'E': dest[i] = '3'; break;
        case 'i': case 'I': dest[i] = '1'; break;
        case 'o': case 'O': dest[i] = '0'; break;
        case 's': case 'S': dest[i] = '$'; break;
        case 't': case 'T': dest[i] = '7'; break;
        default: dest[i] = c;
        }
        i++;
    }
    dest[i] = '\0';
}

// [OTIMIZACAO TCC] Verifica Hash Binário (Híbrido)
// Agora escolhe o melhor caminho dependendo do tamanho da senha
int CheckMatch(const char* senha, unsigned char* targetBin) {
    unsigned char digest[16];
    int len = (int)strlen(senha);

    // Se a senha for curta (99% dos casos), usa o método turbo sem overhead
    if (len < 55) {
        MD5_Fast_OneBlock(senha, len, digest);
    }
    else {
        // Fallback para o método clássico (lento) se for uma frase longa
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, (unsigned char*)senha, len);
        MD5_Final(digest, &ctx);
    }

    // Comparação de memória otimizada
    return (memcmp(digest, targetBin, 16) == 0);
}

// --- WORKER THREAD ---
typedef struct {
    int threadID;
    unsigned char targetBin[16];
    long long startOffset;
    long long endOffset;
} ParametrosThread;

DWORD WINAPI ThreadNeural(LPVOID lpParam) {
    ParametrosThread* p = (ParametrosThread*)lpParam;
    char palavraRaw[128];
    char candidato[512]; // Buffer seguro
    long long i = p->startOffset;
    int k = 0;
    long long tentativas = 0;

    // Limpa lixo de memória
    memset(palavraRaw, 0, sizeof(palavraRaw));

    // Alinhamento inicial (se começou no meio de uma palavra, avança)
    if (i > 0) {
        while (i < p->endOffset && g_KnowledgeBase[i] != '\n') i++;
        i++;
    }

    while (i < p->endOffset && !g_Encontrada) {
        // Extrai palavra
        k = 0;
        // Proteção extra: k < 100 para não estourar buffer e filtrar lixo
        while (g_KnowledgeBase[i] != '\n' && g_KnowledgeBase[i] != '\r' && g_KnowledgeBase[i] != '\0' && k < 100) {
            palavraRaw[k++] = g_KnowledgeBase[i++];
        }
        palavraRaw[k] = '\0';

        // Pula quebras de linha múltiplas
        while (i < p->endOffset && (g_KnowledgeBase[i] == '\n' || g_KnowledgeBase[i] == '\r')) i++;

        if (k == 0) continue;

        // --- HEURÍSTICA ---

        // 1. Original
        if (CheckMatch(palavraRaw, p->targetBin)) { strcpy(candidato, palavraRaw); goto ACHEI; }

        // 2. Minúscula
        char lower[128];
        for (int j = 0; j <= k; j++) lower[j] = tolower(palavraRaw[j]);
        if (CheckMatch(lower, p->targetBin)) { strcpy(candidato, lower); goto ACHEI; }

        // 3. Capitalizada
        char cap[128];
        strcpy(cap, lower); cap[0] = toupper(cap[0]);
        if (CheckMatch(cap, p->targetBin)) { strcpy(candidato, cap); goto ACHEI; }

        // 4. Leet Speak
        char leet[128];
        ApplyLeetSpeak(leet, lower);
        leet[0] = toupper(leet[0]);
        if (CheckMatch(leet, p->targetBin)) { strcpy(candidato, leet); goto ACHEI; }

        // 5. Sufixos Comuns
        const char* SUFIXOS[] = { "123", "123456", "2024", "2025", "!", "@", "BR" };
        for (int s = 0; s < 7; s++) {
            if (g_Encontrada) break;

            sprintf(candidato, "%s%s", cap, SUFIXOS[s]);
            if (CheckMatch(candidato, p->targetBin)) goto ACHEI;

            sprintf(candidato, "%s%s", leet, SUFIXOS[s]);
            if (CheckMatch(candidato, p->targetBin)) goto ACHEI;
        }

        tentativas++;

        // [OTIMIZACAO GUI]
        // 1. Atualiza a cada 50.000 tentativas em vez de 5.000 (reduz overhead)
        // 2. Usa PostMessage (Assíncrono) para não travar a thread de cálculo
        if (p->threadID == 1 && tentativas % 50000 == 0) {
            PostMessageA(hProgress, PBM_STEPIT, 0, 0);
        }
        continue;

    ACHEI:
        g_Encontrada = TRUE;
        char msg[1024];
        sprintf(msg, ">>> SENHA ENCONTRADA! <<<\n\nSenha: %s\nBase: %s\nThread: %d", candidato, palavraRaw, p->threadID);
        MessageBoxA(NULL, msg, "CRACKED", MB_OK | MB_ICONWARNING);
        free(p);
        return 0;
    }
    free(p);
    return 0;
}

// --- SCANNER DE ARQUIVOS ---
void ScanKnowledgeBase() {
    if (g_KnowledgeBase) {
        LogConsole("[INFO] Base ja carregada. Para recarregar, reinicie.");
        return;
    }

    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile("WordLists\\*.txt", &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        LogConsole("[ERRO] Pasta 'WordLists' nao encontrada!");
        return;
    }

    long long totalBytes = 0;
    int fileCount = 0;
    do {
        char path[260];
        sprintf(path, "WordLists\\%s", findData.cFileName);
        FILE* f = fopen(path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            totalBytes += ftell(f);
            fclose(f);
            fileCount++;
            char logMsg[300];
            sprintf(logMsg, " -> %s", findData.cFileName);
            LogConsole(logMsg);
        }
    } while (FindNextFile(hFind, &findData) != 0);
    FindClose(hFind);

    if (totalBytes == 0) return;

    // Alocação com margem de segurança
    long long safeSize = totalBytes + (fileCount * 2) + 1024;

    g_KnowledgeBase = (char*)malloc(safeSize);
    if (!g_KnowledgeBase) { LogConsole("[CRITICAL] Memoria Cheia! Tente x64."); return; }

    hFind = FindFirstFile("WordLists\\*.txt", &findData);
    char* ptrAtual = g_KnowledgeBase;

    do {
        char path[260];
        sprintf(path, "WordLists\\%s", findData.cFileName);
        FILE* f = fopen(path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            fread(ptrAtual, 1, sz, f);
            ptrAtual += sz;
            *ptrAtual = '\n';
            ptrAtual++;
            fclose(f);
        }
    } while (FindNextFile(hFind, &findData) != 0);

    *ptrAtual = '\0';
    g_TotalSize = ptrAtual - g_KnowledgeBase;

    char status[100];
    sprintf(status, "[OK] Base Carregada: %d arquivos | %.2f MB", fileCount, (float)g_TotalSize / 1024 / 1024);
    LogConsole(status);
    EnableWindow(hBtnAtacar, TRUE);
}

// --- GUI ---
HBRUSH hBrushBg, hBrushInput;
HFONT hFont;

LRESULT CALLBACK JanelaProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
    {
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        g_NumCores = sysinfo.dwNumberOfProcessors;

        hBrushBg = CreateSolidBrush(COLOR_BG);
        hBrushInput = CreateSolidBrush(COLOR_INPUT);
        hFont = CreateFont(16, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        CreateWindowA("STATIC", ":: GERADOR DE HASH ::", WS_VISIBLE | WS_CHILD, 20, 10, 300, 20, hwnd, NULL, NULL, NULL);
        hInputSenha = CreateWindowA("EDIT", "Br4s1l", WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 30, 340, 25, hwnd, (HMENU)ID_INPUT_SENHA, NULL, NULL);
        CreateWindowA("BUTTON", "Gerar", WS_VISIBLE | WS_CHILD, 370, 30, 90, 25, hwnd, (HMENU)ID_BTN_GERAR, NULL, NULL);

        CreateWindowA("STATIC", ":: ALVO (Cole o Hash MD5):", WS_VISIBLE | WS_CHILD, 20, 70, 300, 20, hwnd, NULL, NULL, NULL);
        hInputHash = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 90, 440, 25, hwnd, (HMENU)ID_INPUT_HASH, NULL, NULL);

        CreateWindowA("BUTTON", "1. SCANEAR /WordLists", WS_VISIBLE | WS_CHILD, 20, 130, 210, 35, hwnd, (HMENU)ID_BTN_SCAN, NULL, NULL);
        hBtnAtacar = CreateWindowA("BUTTON", "2. INICIAR ATAQUE", WS_VISIBLE | WS_CHILD | WS_DISABLED, 250, 130, 210, 35, hwnd, (HMENU)ID_BTN_ATACAR, NULL, NULL);

        hConsole = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 20, 180, 440, 200, hwnd, (HMENU)ID_CONSOLE, NULL, NULL);
        hProgress = CreateWindowA(PROGRESS_CLASS, "", WS_VISIBLE | WS_CHILD, 20, 390, 440, 10, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);

        SendMessage(hInputSenha, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hInputHash, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hConsole, WM_SETFONT, (WPARAM)hFont, TRUE);

        LogConsole("[SYSTEM] C-Cracker Estavel Iniciado.");
        char cpuMsg[100];
        sprintf(cpuMsg, "[HARDWARE] %d Nucleos detectados.", g_NumCores);
        LogConsole(cpuMsg);
    }
    break;

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND h = (HWND)lParam;
        if (h == hConsole || h == hInputHash || h == hInputSenha) {
            SetTextColor(hdc, COLOR_TEXT);
            SetBkColor(hdc, COLOR_INPUT);
            return (LRESULT)hBrushInput;
        }
        SetTextColor(hdc, RGB(200, 200, 200));
        SetBkColor(hdc, COLOR_BG);
        return (LRESULT)hBrushBg;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BTN_GERAR) {
            char txt[100], res[33];
            GetWindowTextA(hInputSenha, txt, 100);
            CalcularMD5String(txt, res);
            SetWindowTextA(hInputHash, res);
            LogConsole("[GEN] Hash gerado.");
        }

        if (LOWORD(wParam) == ID_BTN_SCAN) {
            ScanKnowledgeBase();
        }

        if (LOWORD(wParam) == ID_BTN_ATACAR) {
            char hashAlvoStr[100];
            GetWindowTextA(hInputHash, hashAlvoStr, 100);

            if (strlen(hashAlvoStr) != 32) {
                LogConsole("[ERRO] Hash invalido.");
            }
            else {
                // RESET DO ESTADO
                g_Encontrada = FALSE;
                LogConsole("--------------------------------");
                LogConsole("[RUN] Processando...");

                SendMessage(hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                SendMessage(hProgress, PBM_SETSTEP, (WPARAM)1, 0);

                unsigned char alvoBin[16];
                HexToBinary(hashAlvoStr, alvoBin);

                long long fatia = g_TotalSize / g_NumCores;
                for (int i = 0; i < g_NumCores; i++) {
                    ParametrosThread* p = (ParametrosThread*)malloc(sizeof(ParametrosThread));
                    memcpy(p->targetBin, alvoBin, 16);
                    p->threadID = i + 1;
                    p->startOffset = i * fatia;
                    if (i == g_NumCores - 1) p->endOffset = g_TotalSize;
                    else p->endOffset = (i + 1) * fatia;
                    CreateThread(NULL, 0, ThreadNeural, p, 0, NULL);
                }
            }
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = JanelaProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "FinalStable";
    wc.hbrBackground = CreateSolidBrush(COLOR_BG);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, "FinalStable", "C-Cracker [STABLE]", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 500, 450, NULL, NULL, hInstance, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}