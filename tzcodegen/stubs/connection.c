#include <connection.h>

#include <stdlib.h>

static Node* connections_head = NULL;

Node* connections_get_head(void) {
    return connections_head;
}

int connections_add(Connection* connection) {
   Node* node = malloc(sizeof(Node));

   if (node == NULL)
      return 0;

   node->connection = *connection;
   node->next = connections_head;
   connections_head = node;
   return 1;
}

Connection* connections_get(uint16_t conn_id) {
    Node* current = connections_head;

    while (current != NULL) {
        Connection* connection = &current->connection;

        if (connection->conn_id == conn_id) {
            return connection;
        }

        current = current->next;
    }

    return NULL;
}

int connections_replace(Connection* connection) {
    Node* current = connections_head;

    while (current != NULL) {
        if (connection->conn_id == current->connection.conn_id) {
            current->connection = *connection;
            return 1;
        }

        current = current->next;
    }

    return 0;
}

//TODO remove this shit
void find_connections(uint16_t io_id, int *arr, uint8_t *num) {
    Node* current = connections_head;
    while (current != NULL) {
        Connection* connection = &current->connection;
        if (connection->io_id == io_id) {
            arr[*num] = connection->conn_id;
            *num = *num + 1;
        }

        current = current->next;
    }

}

void delete_all_connections(void) {
	Node* old = NULL;
	Node* current = connections_head;

    while (current != NULL) {
		old = current;
		current = current->next;
        free(old);
    }

	connections_head = NULL;
}