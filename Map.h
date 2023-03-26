#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	const char* key;
	void* value;
} mapEntry;

static struct LinkedList {
	mapEntry* val;
	struct LinkedList* next;
};

typedef struct {
	struct LinkedList* entries_lst;
	size_t length;
} MAP;

MAP* create_map(void);
void destroy_map(MAP* map);

static const char* map_set_entry(struct LinkedList** entries, const char* key, void* value, size_t* len);
static void map_set_entry_first(struct LinkedList** entries, const char* key, void* value);
static void map_set_entry_between(struct LinkedList** left, struct LinkedList** right, const char* key, void* value);
static void map_set_entry_last(struct LinkedList** entries, const char* key, void* value);
const char* map_set(MAP* map, const char* key, void* value);
size_t map_check_key(MAP* map, const char* key);
void map_delete_key(MAP* map, const char* key);
void* map_get_value(MAP* map, const char* key);
char** map_get_entries(MAP* map);