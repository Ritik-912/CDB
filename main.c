#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#define METADATA_FILE "schema_metadata.bin"
#define BUFFER_SIZE 1024
#define PORT 8080

// Column definition structure
typedef struct {
    char *name;
    char *type; // e.g., "VARCHAR", "INT"
} Column;

// Table schema structure
typedef struct {
    char *table_name;
    size_t column_count;
    Column *columns;
} TableSchema;

// Row structure for dynamic data storage
typedef struct {
    size_t column_count;
    char **values; // Array of strings representing column values
} Row;

// Function prototypes
void encrypt_password(const char *password, char **encrypted);
void handle_client(int client_socket);
void process_command(const char *command, char *response);
bool create_table(const char *table_name, size_t column_count, Column *columns);
bool insert_into_table(const char *table_name, Row *row);
Row *select_from_table(const char *table_name, const char *condition_column, const char *condition_value);
bool update_table(const char *table_name, const char *condition_column, const char *condition_value, Row *updated_row);
bool delete_from_table(const char *table_name, const char *condition_column, const char *condition_value);
void free_row(Row *row);
void free_schema(TableSchema *schema);

// Strong password encryption using OpenSSL
void encrypt_password(const char *password, char **encrypted) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, &length);
    EVP_MD_CTX_free(mdctx);

    *encrypted = malloc(length * 2 + 1);
    for (unsigned int i = 0; i < length; i++) {
        sprintf((*encrypted) + i * 2, "%02x", hash[i]);
    }
    (*encrypted)[length * 2] = '\0';
}

// Create a table by defining its schema
bool create_table(const char *table_name, size_t column_count, Column *columns) {
    FILE *file = fopen(METADATA_FILE, "ab");
    if (!file) return false;

    size_t name_len = strlen(table_name) + 1;
    fwrite(&name_len, sizeof(size_t), 1, file);
    fwrite(table_name, sizeof(char), name_len, file);
    fwrite(&column_count, sizeof(size_t), 1, file);

    for (size_t i = 0; i < column_count; i++) {
        size_t col_name_len = strlen(columns[i].name) + 1;
        size_t col_type_len = strlen(columns[i].type) + 1;

        fwrite(&col_name_len, sizeof(size_t), 1, file);
        fwrite(columns[i].name, sizeof(char), col_name_len, file);
        fwrite(&col_type_len, sizeof(size_t), 1, file);
        fwrite(columns[i].type, sizeof(char), col_type_len, file);
    }

    fclose(file);

    // Create a binary file for the table data
    char table_file[BUFFER_SIZE];
    sprintf(table_file, "%s.bin", table_name);
    FILE *table_data_file = fopen(table_file, "wb");
    if (!table_data_file) return false;
    fclose(table_data_file);

    return true;
}

// Insert a row into a table
bool insert_into_table(const char *table_name, Row *row) {
    char table_file[BUFFER_SIZE];
    sprintf(table_file, "%s.bin", table_name);
    FILE *file = fopen(table_file, "ab");
    if (!file) return false;

    fwrite(&row->column_count, sizeof(size_t), 1, file);
    for (size_t i = 0; i < row->column_count; i++) {
        size_t value_len = strlen(row->values[i]) + 1;
        fwrite(&value_len, sizeof(size_t), 1, file);
        fwrite(row->values[i], sizeof(char), value_len, file);
    }

    fclose(file);
    return true;
}

// Select rows from a table
Row *select_from_table(const char *table_name, const char *condition_column, const char *condition_value) {
    // Functionality to find rows matching condition_column and condition_value
    // Skipping implementation for brevity
    return NULL;
}

// Update rows in a table
bool update_table(const char *table_name, const char *condition_column, const char *condition_value, Row *updated_row) {
    // Functionality to update rows based on condition_column and condition_value
    // Skipping implementation for brevity
    return false;
}

// Delete rows from a table
bool delete_from_table(const char *table_name, const char *condition_column, const char *condition_value) {
    // Functionality to delete rows based on condition_column and condition_value
    // Skipping implementation for brevity
    return false;
}

// Free dynamically allocated Row
void free_row(Row *row) {
    if (!row) return;
    for (size_t i = 0; i < row->column_count; i++) {
        free(row->values[i]);
    }
    free(row->values);
    free(row);
}

// Free dynamically allocated TableSchema
void free_schema(TableSchema *schema) {
    if (!schema) return;
    for (size_t i = 0; i < schema->column_count; i++) {
        free(schema->columns[i].name);
        free(schema->columns[i].type);
    }
    free(schema->columns);
    free(schema);
}

// Process API command
void process_command(const char *command, char *response) {
    char action[BUFFER_SIZE];
    sscanf(command, "%s", action);

    if (strcmp(action, "CREATE_TABLE") == 0) {
        // Parse and create table
        // Example: CREATE_TABLE table_name col1:VARCHAR col2:INT
        char table_name[BUFFER_SIZE];
        size_t column_count;
        Column *columns = NULL;

        // Parse table_name and columns dynamically (skipping implementation details for brevity)
        // Add table creation logic here

        if (create_table(table_name, column_count, columns)) {
            sprintf(response, "Table %s created successfully.\n", table_name);
        } else {
            sprintf(response, "Failed to create table %s.\n", table_name);
        }

        // Free columns after use
        for (size_t i = 0; i < column_count; i++) {
            free(columns[i].name);
            free(columns[i].type);
        }
        free(columns);
    } else if (strcmp(action, "INSERT") == 0) {
        // Parse and insert into table
        // Example: INSERT table_name col1_value col2_value
        // Add insert logic here
    } else if (strcmp(action, "SELECT") == 0) {
        // Parse and select from table
        // Example: SELECT table_name condition_column condition_value
        // Add select logic here
    } else if (strcmp(action, "UPDATE") == 0) {
        // Parse and update table
        // Example: UPDATE table_name condition_column condition_value new_values
        // Add update logic here
    } else if (strcmp(action, "DELETE") == 0) {
        // Parse and delete from table
        // Example: DELETE table_name condition_column condition_value
        // Add delete logic here
    } else {
        sprintf(response, "Invalid command.\n");
    }
}

// Main function
int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Failed to create socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    listen(server_socket, 3);
    printf("Server listening on port %d\n", PORT);

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len))) {
        printf("Connection accepted.\n");
        handle_client(client_socket);
    }

    close(server_socket);
    return 0;
}
