#include "filemap.h"
#include <stdlib.h>
#include <string.h>

FileMap* createFileMap() {
    FileMap* map = malloc(sizeof(FileMap));
    if (map) {
        map->head = NULL;
    }
    return map;
}

void addToFileMap(FileMap *map, FILE *file, const char *filename) {
    if (map == NULL || file == NULL || filename == NULL) return;

    FileMapNode *newNode = malloc(sizeof(FileMapNode));
    if (newNode == NULL) return;

    newNode->file = file;
    newNode->filename = strdup(filename);
    newNode->next = map->head;
    map->head = newNode;
}

char* findFilenameByFile(FileMap *map, FILE *file) {
    if (map == NULL) return NULL;
    FileMapNode *current = map->head;

    while (current != NULL) {
        if (current->file == file) {
            return current->filename;
        }
        current = current->next;
    }
    return NULL;
}
