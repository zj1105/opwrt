#include <stdio.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <string.h>


#define MAX 1024
const char *json_get_string_value_by_field(struct json_object *json, const char *p_field);
int json_get_int_value_by_field(struct json_object *json, const char *p_field);
const char *json_get_string_value(struct json_object *json);
int json_get_int_value_by_field(struct json_object *json, const char *p_field);
struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field);
int json_is_array(struct json_object *json);




void handle_post_request();
void handle_get_request();
void parse_post_data(const char *data, char *action, char *param);

//{"action":"getnetwork","param":{}}
//{"action":"login","param":{"amin":"root","passwd":"123456789"}}
int main() {

  const char* method = getenv("REQUEST_METHOD");
  // Print HTTP header
  printf("Content-Type: application/json\n\n");

  if (method != NULL && strcmp(method, "POST") == 0) {
      handle_post_request();
  } else if (method != NULL && strcmp(method, "GET") == 0) {
      handle_get_request();
  } else {
      // Method not supported
      printf("{\"error\":1,\"message\":\"Method not supported\"}\n");
  } 
   
  return 0;
}


void handle_post_request() {
  char action[64];
  char param[64];
  char query[MAX];
  size_t content_length;
  char* content_length_str = getenv("CONTENT_LENGTH");
  if(content_length_str == NULL) {
    printf("{\"error\":2,\"message\":\"Miss content_length\"}");
    return;
  }
  
  content_length = (size_t)atoi(content_length_str);
  if(content_length > MAX) {
    printf("{\"error\":3,\"message\":\"content_length is too large\"}");
    return;
  }
  
  fread(query, 1, content_length, stdin);
  query[content_length] = '\0';
  
  parse_post_data(query,action, param);
  
}

void handle_get_request() {
  printf("{\"error\":11,\"message\":\"don't support GET method\"}");
}


// Function to parse POST data (JSON format)
void parse_post_data(const char *data, char *action, char* param) {
    // Parse JSON input using json-c
    struct json_object *parsed_json = NULL;
    struct json_object *json_param = NULL;
   // struct json_object *json_action = NULL;

    parsed_json = json_tokener_parse(data);
    
    action = json_get_string_value_by_field(parsed_json, "action");
    
    if(!strcmp(action, "login")) {
      json_param = json_get_json_object_by_field(parsed_json, "param");
      char *admin = json_get_string_value_by_field(json_param, "admin");
      char *passwd = json_get_string_value_by_field(json_param, "passwd");
      
      if(!strcmp(admin, "admin") && !strcmp(passwd, "123456789")) {
        printf("{\"error\":0}");
      } else {
        printf("{\"error\":7,\"message\":\"account or passwd failed\"}");
        return;
      }
    } else if(!strcmp(action,"vv")) {
      
    } else {
      printf("{\"error\":66,\"message\":\"not found this action\"}");
      return;
    }
    /*if (json_object_object_get_ex(parsed_json, "module", &json_module)) {
        strncpy(module, json_object_get_string(json_module), sizeof(module) - 1);
    }

    if (json_object_object_get_ex(parsed_json, "param", &json_action)) {
        struct json_object *json_action_value;
        if (json_object_object_get_ex(json_action, "action", &json_action_value)) {
            strncpy(action, json_object_get_string(json_action_value), sizeof(action) - 1);
        }
    }*/

    json_object_put(json_param);
   // json_object_put(josn_action);
    json_object_put(parsed_json); // Free the memory of JSON object
}



const char *json_get_string_value_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *string_json = NULL;

    json_object_object_get_ex(json, p_field, &string_json);
    if (NULL == string_json)
    {
        printf("json_object_object_get error %s", p_field);
        return NULL;
    }

    if (json_type_string == json_object_get_type(string_json))
    {
        return json_object_get_string(string_json);
    }

    return NULL;
}

int json_get_int_value_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *int_json = NULL;

    json_object_object_get_ex(json, p_field, &int_json);
    if (NULL == int_json)
    {
        printf("json_object_object_get error %s", p_field);
        return -1;
    }

    if (json_type_int == json_object_get_type(int_json))
    {
        return (int)json_object_get_int(int_json);
    }

    return -1;
}

const char *json_get_string_value(struct json_object *json)
{
    if (json_type_string == json_object_get_type(json))
    {
        return json_object_get_string(json);
    }

    return NULL;
}

struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *json_obj = NULL;

    json_object_object_get_ex(json, p_field, &json_obj);
    if (NULL == json_obj)
    {
        printf("json_object_object_get error %s", p_field);
        return NULL;
    }

    return json_obj;
}

int json_is_array(struct json_object *json)
{
    if (json_type_array == json_object_get_type(json))
    {
        return 0;
    }

    return -1;
}


