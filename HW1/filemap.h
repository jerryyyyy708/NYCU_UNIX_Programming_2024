#ifndef FILEMAP_H
#define FILEMAP_H

#include <stdio.h>

typedef struct FileMapNode {
    FILE *file;
    char *filename;
    struct FileMapNode *next;
} FileMapNode;

typedef struct {
    FileMapNode *head;
} FileMap;

FileMap* createFileMap();
void addToFileMap(FileMap *map, FILE *file, const char *filename);
char* findFilenameByFile(FileMap *map, FILE *file);

#endif // FILEMAP_H
