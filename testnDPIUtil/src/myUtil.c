/*
 * myUtil.c
 *  This file is for some support functions for this ndpi_util
 *  Created on: Sep 16, 2017
 *      Author: Xiao Wang
 */

#include <ndpi_api.h>

u_int32_t current_ndpi_memory, max_ndpi_memory;

void set_ndpi_flow_malloc(void* (*__ndpi_flow_malloc)(size_t size)) {
	//do nothing, indicating use below defined method
}
void set_ndpi_flow_free(void  (*__ndpi_flow_free)(void *ptr)) {
	//do nothing, indicating use below defined method
}

void ndpi_flow_free(void *ptr) {
	ndpi_free_flow((struct ndpi_flow_struct *) ptr);
}
void * ndpi_flow_malloc(size_t size) {
	return ndpi_malloc(size);
}

