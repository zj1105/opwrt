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
}


int execute_command(const char *cmd, char *output, size_t size) {
	
	char buf[MAX_SIZE] = {0};
	size_t current_size = 0;
	FILE *fp = popen(cmd, "r");
	if(fp == NULL) {
		perror("popen failed\n");
		output[0] = '\0';
		return -1;
	}
	
	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		size_t len = strlen(buf);
		if(len + current_size < size -1) {
			strcpy(output + current_size, buf);
			current_size += len;
		}
	}
	
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
        printf("%s",json_object_to_json_string(myJson));

	json_object_put(oipaddr);
	json_object_put(onetmask);
	json_object_put(oip6assign);
	json_object_put(omulticast_querier);
	json_object_put(oigmp_snooping);
	json_object_put(oieee1905managed);
	json_object_put(myJson);

    } else if(!strcmp("GetVersion",action)) {
		char openwrt[MAX_SIZE] = {0};
		char kernel[MAX_SIZE] = {0};
		char fw_version[MAX_SIZE] = {0};
		char full_fw_version[MAX_SIZE] = {0};
		char vendor_version[MAX_SIZE] = {0};
		
		execute_command("cat /etc/openwrt_version", openwrt,MAX_SIZE);
		execute_command("uname -r", kernel, MAX_SIZE);
		
		get_value_config("FW_VERSION",fw_version);
		get_value_config("VENDOR_ASKEY_VERSION",vendor_version);
		get_value_config("FULL_FW_VERSION",full_fw_version);

        struct json_object *Version_json = json_object_new_object();
        json_object_object_add(Version_json,"openwrt",json_object_new_string(openwrt));
        json_object_object_add(Version_json,"kernel",json_object_new_string(kernel));
        json_object_object_add(Version_json,"fw_version",json_object_new_string(fw_version));
        json_object_object_add(Version_json,"full_fw_version",json_object_new_string(fw_version));
        json_object_object_add(Version_json,"vendor_version",json_object_new_string(vendor_version));
        printf("%s",json_object_to_json_string(Version_json));

	} else if(!strcmp(action, "setDHCP")) {
        char cmd[512] = {0};
        char *mipaddr = json_get_string_value_by_field(parsed_json,"ipaddr");
        char *mnetmask = json_get_string_value_by_field(parsed_json,"netmask");
        char *mlimit = json_get_string_value_by_field(parsed_json, "limit");
        char *mstart = json_get_string_value_by_field(parsed_json, "start");
        char *mleasetime = json_get_string_value_by_field(parsed_json, "leasetime");

        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.ipaddr=%s", mipaddr);
        system(cmd);

        sprintf(cmd,"uci set network.lan.netmask=%s", mnetmask);
        system(cmd);

        sprintf(cmd,"uci set network.lan.limit=%s", mlimit);
        system(cmd);

        sprintf(cmd,"uci set network.lan.start=%s", mstart);
        system(cmd);

        sprintf(cmd,"uci set network.lan.leasetime=%s", mleasetime);
        system(cmd);

        system("uci commit");
        system("/etc/init.d/network restart");

        printf("{\"error\":0}");
    } else if(!strcmp(action, "setWIFI")){
        
    } else {
        	printf("{\"error\":66,\"message\":\"not found this action\"}");
        	return;
    }
    json_object_put(json_param);
 
    json_object_put(parsed_json); // Free the memory of JSON object
}


void get_value_config(const char *key,char *value) {
    size_t value_size = MAX_SIZE;
	char line[MAX_SIZE] = {0};
	FILE *file = fopen("/etc/system_version.info","r");
    if(file == NULL) {
        perror("fopen file failed");
        return;
    } 
	
	while(fgets(line, sizeof(line) - 1, file) != NULL) {
		char *pos = strchr(line, '=');
        if(pos == NULL ) {
            perror("find = failed");
            return;
        }
        *pos = '\0';
        char *current_key = line;
        char *current_value = pos + 1;
        char *new_pos = strchr(current_value, '\n');
        if(new_pos != NULL) {
            *new_pos = '\0';
        }
        if(!strcmp(key, current_key)) {
            //size_t value_size = sizeof(current_value);
            if(strlen(current_value) < value_size) {
                strncpy(value,current_value, value_size - 1);
                value[value_size - 1] = '\0';
            } else {
                printf("\"error\":12138,\"message\":\"value len is too large\"\n");
            }
        }
        
	}

    fclose(file);
	
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


