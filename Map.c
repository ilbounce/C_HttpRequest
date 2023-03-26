#include "Map.h"

MAP* create_map(void)
{
	MAP* map = malloc(sizeof(MAP));
	map->length = 0;
	return map;
}

static void map_set_entry_first(struct LinkedList** entries, const char* key, void* value)
{
	struct LinkedList* head = malloc(sizeof(struct LinkedList));
	head->val = malloc(sizeof(mapEntry));
	head->next = malloc(sizeof(struct LinkedList));
	head->val->key = key;
	head->val->value = value;
	head->next = (*entries);
	(*entries) = head;
}

static void map_set_entry_between(struct LinkedList** left, struct LinkedList** right, const char* key, void* value)
{
	struct LinkedList* node = malloc(sizeof(struct LinkedList));
	node->val = malloc(sizeof(mapEntry));
	node->next = malloc(sizeof(struct LinkedList));
	node->val->key = key;
	node->val->value = value;
	node->next = (*right);
	(*left)->next = node;
}

static void map_set_entry_last(struct LinkedList** entries, const char* key, void* value)
{
	(*entries)->next = malloc(sizeof(struct LinkedList));
	(*entries)->next->val = malloc(sizeof(mapEntry));
	(*entries)->next->val->key = key;
	(*entries)->next->val->value = value;
	(*entries)->next->next = NULL;
}

static const char* map_set_entry(struct LinkedList** entries, const char* key, void* value, size_t* len)
{
	if (*len == 0)
	{
		*entries = malloc(sizeof(struct LinkedList));
		(*entries)->val = malloc(sizeof(mapEntry));
		(*entries)->next = NULL;
		(*entries)->val->key = key;
		(*entries)->val->value = value;
		(*len)++;
	}

	else
	{
		struct LinkedList* start = *entries;
		struct LinkedList* last = NULL;
		struct LinkedList* prev = start;

		do
		{
			struct LinkedList* current = start;
			struct LinkedList* nxt = start->next;

			while (nxt != last)
			{
				nxt = nxt->next;
				if (nxt != last) {
					prev = current;
					current = current->next;
					nxt = nxt->next;
				}
			}

			if (strcmp(current->val->key, key) == 0) {
				current->val->value = value;
				break;
			}

			else if (strcmp(current->val->key, key) < 0) {
				prev = current;
				start = current->next;

				if (start == NULL) {
					map_set_entry_last(&prev, key, value);
					(*len)++;
					break;
					/*last = current;
					start = current;*/
				}

				else if (strcmp(start->val->key, key) > 0)
				{
					map_set_entry_between(&prev, &start, key, value);
					(*len)++;
					break;
					/*last = current;
					start = current;*/
				}
			}

			else {
				if (prev == current->next || prev == current) {
					map_set_entry_first(entries, key, value);
					(*len)++;
					break;
					//start = current;
				}
				else if (strcmp(prev->val->key, key) < 0) {
					map_set_entry_between(&prev, &current, key, value);
					(*len)++;
					break;
					//start = current;
				}
				last = current;
			}
		} while (last == NULL || last != start);
	}

	return key;
}

const char* map_set(MAP* map, const char* key, void* value)
{
	if (value == NULL) {
		return NULL;
	}
	return map_set_entry(&map->entries_lst, key, value, &map->length);
}

void* map_get_value(MAP* map, const char* key)
{
	struct LinkedList* start = map->entries_lst;
	struct LinkedList* last = NULL;

	do
	{
		struct LinkedList* current = start;
		struct LinkedList* nxt = start->next;

		while (nxt != last)
		{
			nxt = nxt->next;
			if (nxt != last) {
				current = current->next;
				nxt = nxt->next;
			}
		}

		if (strcmp(current->val->key, key) == 0) {
			return current->val->value;
		}

		else if (strcmp(current->val->key, key) < 0) {
			start = current->next;
		}

		else {
			last = current;
		}
	} while (last == NULL || last != start);

	return NULL;
}

size_t map_check_key(MAP* map, const char* key)
{
	if (map_get_value(map, key) == NULL) {
		return 0;
	}

	else return 1;
}

void map_delete_key(MAP* map, const char* key)
{
	if (strcmp(map->entries_lst->val->key, key) == 0)
	{
		struct LinkedList* tmp = map->entries_lst;
		if (tmp->next == NULL)
		{
			free(tmp->val);
			free(map->entries_lst);
		}
		else
		{
			map->entries_lst = map->entries_lst->next;
			free(tmp->val);
			free(tmp);
		}

		map->length--;
	}

	else
	{
		struct LinkedList* start = map->entries_lst;
		struct LinkedList* last = NULL;
		struct LinkedList* prev = start;
		do
		{
			struct LinkedList* current = start;
			struct LinkedList* nxt = start->next;

			while (nxt != last)
			{
				nxt = nxt->next;
				if (nxt != last) {
					prev = current;
					current = current->next;
					nxt = nxt->next;
				}
			}

			if (strcmp(current->val->key, key) == 0) {
				struct LinkedList* tmp = current;
				prev->next = current->next;
				free(tmp->val);
				free(tmp);
				map->length--;
				break;
			}

			else if (strcmp(current->val->key, key) < 0) {
				prev = current;
				start = current->next;
			}

			else {
				last = current;
			}
		} while (last == NULL || last != start);
	}
}

char** map_get_entries(MAP* map) 
{
	if (map->length == 0) {
		return NULL;
	}
	char** output = (char**)malloc(map->length * sizeof(char*));
	struct LinkedList* current = map->entries_lst;
	for (register int i = 0; i < map->length; i++) {
		output[i] = current->val->key;
		current = current->next;
	}

	return output;
}

void destroy_map(MAP* map) {
	struct LinkedList* tmp;
	while (map->entries_lst != NULL) {
		tmp = map->entries_lst;
		map->entries_lst = map->entries_lst->next;
		free(tmp->val);
		free(tmp);
	}

	free(map);
}