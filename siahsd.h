
typedef struct {
	char *database_host;
	char *database_username;
	char *database_password;
	char *database_name;
	char *database_driver;
	gint siahs_port;
	char *log_file;
	gint log_level;
	gboolean foreground;
	char *pid_file;
} configuration;

#define DEBUG(level, args...) debug(level, __location__, __FUNCTION__, args)

typedef enum {
	ST_OK = 0,
	ST_GENERAL_FAILURE = 1,
	ST_NO_SUCH_OBJECT = 2,
	ST_READ_ERROR = 3,
	ST_WRITE_ERROR = 4,
	ST_LOG_ERR = 117,
	ST_DATABASE_FAILURE = 118,
	ST_BIND_FAILURE = 119,
	ST_SOCKET_FAILURE = 120,
	ST_CONFIGURATION_ERROR = 121,
	ST_ASSERTION_FAILED = 122,
	ST_NOT_IMPLEMENTED = 123,
	ST_OUT_OF_MEMORY = 124,
} STATUS;

#define NO_MEM_RETURN(ptr) {if (ptr == NULL) { DEBUG(0, "Out of memory"); return ST_OUT_OF_MEMORY; }}
#define NO_MEM_RETURN_RV(ptr, rv) {if (ptr == NULL) { DEBUG(0, "Out of memory"); return rv; }}
