#ifndef NODE_H
#define NODE_H

#include "common.h"
#include "common_share.h"
#include "puf_data.h"


//node handler
typedef struct node_s node_t; 

typedef struct{
    io_interface_t io;
} node_dependencies_t;

node_t* node_create(node_id_t node_id, node_dependencies_t deps);
void node_destroy(node_t* node);

void run_node_state(node_t* node);
void node_set_update_data(node_t* node, const update_t* data, size_t len);

#endif