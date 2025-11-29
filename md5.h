#pragma once
#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <string.h>

// Estrutura de Contexto do MD5
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} MD5_CTX;

// Protótipos Padrão
void MD5_Init(MD5_CTX* context);
void MD5_Update(MD5_CTX* context, const unsigned char* input, unsigned int inputLen);
void MD5_Final(unsigned char digest[16], MD5_CTX* context);

// --- NOVAS FUNÇÕES ---

// Função Otimizada para o loop de ataque (Ignora overhead de structs)
void MD5_Fast_OneBlock(const char* input, int len, unsigned char* digest);

// Função auxiliar para a GUI
void CalcularMD5String(const char* senha, char* saidaHex);

#endif