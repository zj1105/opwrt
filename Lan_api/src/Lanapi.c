#include <stdio.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <string.h>


#define MAX 1024
#define MAX_SIZE 1024
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
	/*char action[MAX_SIZE];
	char param[MAX];
	char buf[MAX_SIZE];
	char *content_length_str = getenv("CONTENT_LENGTH");
	if(content_length_str == NULL) {
		printf("{\"error\":2,\"message\":\"Miss content_length\"}");
		return;
	}
	
	content_length = (size_t)atoi(content_length_str);
	if(content_length >= MAX) {
		printf("{\"error\":3,\"message\":\"content length is too large\"}");
		return;
	}

	fread(buf, 1, content_length, stdin);
	buf[content_length] = '\0';
	
	parse_get_data(buf,action,param);*/
}

/*void parse_post_getdhcp(const char *data, char *action, char *param) {
	struct json_object *parsed_josn = NULL;
	parsed_josn = json_tokener_parse(data);
	action = json_get_string_value_by_field(parsed_json, "action");
	char response[MAX_SIZE];
	char ipaddr[MAX_SIZE] = {0};
	char netmask[MAX_SIZE] = {0};
	char ip6assign[MAX_SIZE] = {0};
	char multicast_querier[MAX_SIZE] = {0};
	char igmp_snooping[MAX_SIZE] = {0};
	char ieee1905managed[MAX_SIZE] = {0};
	if(!strcmp(action, "getdhcp")) {
		execute_command("uci get network.lan.ipaddr", ipaddr,MAX_SIZE);
		execute_command("uci get network.lan.netmask", netmask, MAX_SIZE);
		execute_command("uci get network.lan.ip6assign", ip6assign, MAX_SIZE);
		execute_command("uci get network.lan.multicast_querier", multicast_querier, MAX_SIZE);
		execute_command("uci get network.lan.igmp_snooping", igmp_snooping, MAX_SIZE);
		execute_command("uci get network.lan.iee1905managed", iee1905managed, MAX_SIZE);
		
		struct json_object *oipaddr = json_object_new_string(ipaddr);
		struct json_object *onetmask = json_object_new_string(netmask);
		struct json_object *oip6assign = json_object_new_string(ip6assign);
		struct json_object *omulticast_querier = json_object_new_string(multicast_querier);
		struct json_object *oigmp_snooping = json_object_new_string(igmp_snooping);
		struct json_object *oiee1905managed = json_object_new_string(ieee1905managed);

		struct json_object *myJson = NULL;
		json_object_object_add(myJson,"ipaddr",oipaddr);
		json_object_object_add(myJson,"netmask",onetmask);
		json_object_object_add(myJson,"ip6assogn",oip6assign);
		json_object_object_add(myJson,"multicast_querier",omulticast_querier);
		json_object_object_add(myJson,"igmp_snooping"<oigmp_snooping;
		json_object_object_add(myJson,"ieee1905managed",oieee1905managed);
		
		strcpy(response,json_object_to_json_string(myJson));
		printf("%s",response);
		
	}
}*/

int execute_command(const char *cmd, char *output, size_t size) {
	
	char buf[MAX_SIZE] = {0};
	size_t current_size = 0;
	FILE *fp = popen(cmd, "r");
	if(fp == NULL) {
		perror("popen failed\n");
		//output[0] = '\0';
	//	printf("{\"error\":123}");
		return -1;
	}
	
	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		size_t len = strlen(buf);
		if(len + current_size < size -1) {
			strcpy(output + current_size, buf);
			current_size += len;
		//	printf("\"{buf\":%s}",buf);
		}
	}
//	printf("{\"body\":%s\n}",output);
//	output[size] = '\0';
	
	if(pclose(fp) == -1) {
		perror("pclose failed\n");
		return -1;
	}
	return 0;
}
// Function to parse POST data (JSON format)
void parse_post_data(const char *data, char *action, char* param) {
    // Parse JSON input using json-c
    struct json_object *parsed_json = NULL;
    struct json_object *json_param = NULL;
   // struct json_object *json_action = NULL;

    parsed_json = json_tokener_parse(data);
    
    action = json_get_string_value_by_field(parsed_json, "action");
    


    	char response[MAX_SIZE] = {0};
        char ipaddr[MAX_SIZE] = {0};
        char netmask[MAX_SIZE] = {0};
        char ip6assign[MAX_SIZE] = {0};
        char multicast_querier[MAX_SIZE] = {0};
        char igmp_snooping[MAX_SIZE] = {0};
        char ieee1905managed[MAX_SIZE] = {0};




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
    } else if(!strcmp(action, "getdhcp")) {
		execute_command("uci get network.lan.ipaddr", ipaddr,MAX_SIZE);
            	  // printf("{\"error\":0,\"ipaddr\":\"%s\"}",ipaddr);
		execute_command("uci get network.lan.netmask", netmask, MAX_SIZE);
                execute_command("uci get network.lan.ip6assign", ip6assign, MAX_SIZE);
                execute_command("uci get network.lan.multicast_querier", multicast_querier, MAX_SIZE);
                execute_command("uci get network.lan.igmp_snooping", igmp_snooping, MAX_SIZE);
                execute_command("uci get network.lan.ieee1905managed", ieee1905managed, MAX_SIZE);

                struct json_object *oipaddr = json_object_new_string(ipaddr);
                struct json_object *onetmask = json_object_new_string(netmask);
                struct json_object *oip6assign = json_object_new_string(ip6assign);
                struct json_object *omulticast_querier = json_object_new_string(multicast_querier);
                struct json_object *oigmp_snooping = json_object_new_string(igmp_snooping);
                struct json_object *oieee1905managed = json_object_new_string(ieee1905managed);

                struct json_object *myJson = NULL;
                myJson = json_object_new_object();
		json_object_object_add(myJson,"ipaddr",oipaddr);
                json_object_object_add(myJson,"netmask",onetmask);
                json_object_object_add(myJson,"ip6assign",oip6assign);
                json_object_object_add(myJson,"multicast_querier",omulticast_querier);
                json_object_object_add(myJson,"igmp_snooping",oigmp_snooping);
                json_object_object_add(myJson,"ieee1905managed",oieee1905managed);

                //strcpy(response,json_object_to_json_string(myJson));
                printf("%s",json_object_to_json_string(myJson));

		json_object_put(oipaddr);
		json_object_put(onetmask);
		json_object_put(oip6assign);
		json_object_put(omulticast_querier);
		json_object_put(oigmp_snooping);
		json_object_put(oieee1905managed);
		json_object_put(myJson);

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


