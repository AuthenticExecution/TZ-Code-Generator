#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <inttypes.h>
#include <crypto.h>

typedef struct
{
    uint8_t  encryption;
	uint16_t conn_id;
    uint16_t io_id;
    uint16_t nonce;
    key_t connection_key;
} Connection;

typedef struct Node {
    Connection connection;
    struct Node* next;
} Node;

Node* connections_get_head(void);
int connections_add(Connection* connection);
Connection* connections_get(uint16_t conn_id);
int connections_replace(Connection* connection);
void delete_all_connections(void);

#endif