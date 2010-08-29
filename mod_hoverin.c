#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <util_filter.h>
#include <http_config.h>
#include <apr_strmatch.h>
#include <apr_hash.h>


/* All function names starting with hoverin : like a namespace */
module AP_MODULE_DECLARE_DATA hoverin_module  ;

/* per-dir-configuration data structure for the module */
typedef struct {
	const char *header;
	const char *footer;
	apr_table_t *hosts;
} hoverin_dir_cfg;

/* filter context data structure: f->ctx */
typedef struct {
	apr_bucket *head;
	apr_bucket *foot;
	apr_table_t *hosts;
	unsigned int state;
} hoverin_ctx;

typedef struct {
	apr_table_t *params_table
} r_cfg;
/** A hash table for storing get parameters of the request */
//static apr_table_t *params_table;


/* Name of the filter-module */
static const char *name = "hoverin-filter";

//static int count = 0;


#define TXT_HEAD 0x01
#define TXT_FOOT 0x02

/*  a utility function that reads the header and footer files and returns them 
*	in the form of a file bucket
*	params:
*		@r: a request_rec object that represents the current request_rec
*		@fname: the name of the file that needs to be read
*	returns: apr_butcket * : a file bucket 
*/
static apr_bucket* hoverin_file_bucket(request_rec *r, const char *fname)
{
    apr_file_t *file = NULL;
	apr_finfo_t finfo;
	if ( apr_stat(&finfo, fname, APR_FINFO_SIZE, r->pool) != APR_SUCCESS ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_hoverin: stat error");
		return NULL;
	}
	if ( apr_file_open(&file, fname, APR_READ | APR_SHARELOCK | 
		APR_SENDFILE_ENABLED, APR_OS_DEFAULT, r->pool) != APR_SUCCESS ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
					  "mod_hoverin: cant open the file");
		return NULL;
	}
	if ( !file ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_hoverin: invalid file");
		return NULL;
	}
	return apr_bucket_file_create(file, 0, finfo.size, r->pool,
								  r->connection->bucket_alloc);
}




/**
	A simplified implementation of a get parameter parser.
	It simply takes the querystring from the request object and stores the
	parameters in a hash table in key value format. No support for multiple
	valued parameters as is the case in our module.
*/
static void parse_get_params(request_rec *r, const char *querystring)
{
	const char *delim = "&";
	char *pair;
	char *last;
	char *ch;
	char *value;
	const char *token;
	//params_table = apr_table_make(r->pool, 6);
	//apr_table_t *params_table = ap_get_module_config(r->request_config, &hoverin_module);
	r_cfg *my_r_cfg = ap_get_module_config(r->request_config, &hoverin_module);
	my_r_cfg->params_table = apr_table_make(r->pool, 6);
	apr_table_t *params_table = my_r_cfg->params_table;
	
	if (querystring == NULL) {
		return;
	}
	
	/*for (pair = (char *) apr_strtok(querystring, delim, &last);
		 pair != NULL; 
		 pair = (char *) apr_strtok(NULL, delim, &last)) {*/
	while (*querystring && (pair = ap_getword(r->pool, (const char **) &querystring, '&'))) {
		/**
		*	replace + in the current key-value pair with blank spaces 
		*/
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "pair = %s", pair);
		for (ch = pair; *ch; ++ch) {
			if (*ch == '+') {
				*ch = ' ';
			}
		}
		
		/**
		*	Now separate the key and value and store them in the table 
		*/
		ch = NULL;
		ch = ap_strchr_c(pair, '=');
		if (ch != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ch = %s", ch);
			*ch++ = '\0';
			ap_unescape_url(pair);
			ap_unescape_url(ch);
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ch is null");
			ch = "";
			ap_unescape_url(pair);
		}		
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "key=%s, val=%s", pair, ch);
		apr_table_set(params_table, pair, ch);
	}
	//return params_table;
}

static void parse_query(request_rec *r)
{
	
	r_cfg *my_r_cfg = apr_palloc(r->pool, sizeof(r_cfg));
	//apr_table_t	*params_table = apr_table_make(r->pool, 6);
	//ap_set_module_config(r->request_config, &hoverin_module, params_table);
	ap_set_module_config(r->request_config, &hoverin_module, my_r_cfg);
	my_r_cfg->params_table = NULL;
	//parse_get_params(r, r->parsed_uri.query);
	
}

/**
*	Function to extract the value of a given request parameter from
*	params_table.
*	params:
*		@r: the request object
*		@param: the parameter whose value is to be found
*	Returns:
*		value of the parameter if found an entry for the param is found in the
*		table.
*		NULL if there is no entry of the given parameter in the table.
*/

static const char *get_parameter(request_rec *r, const char *param)
{
	if (r == NULL || param == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "r or param is null");
		return;
	}
	//apr_table_t *params_table = NULL;
	//apr_table_t *params_table = ap_get_module_config(r->request_config, &hoverin_module);
	//apr_table_t *params_table = apr_table_make(r->pool, 6);
	//parse_get_params(r, r->parsed_uri.query);
	r_cfg  *my_r_cfg = ap_get_module_config(r->request_config, &hoverin_module);
	apr_table_t *params_table = my_r_cfg->params_table;
	if (params_table == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "table is null");
		//params_table = parse_get_params(r, r->parsed_uri.query);
	}
	
	
	const char *val = apr_table_get(params_table, param);
	/**
	*	If the value of the parameter is NULL then return ''
	*/
	if (val == NULL) {
		return "";
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "value = %s", val);
	return val;
}

/** insert_text function inserts the specified text in the bucket brigade at
*	the specified place (text and place are string parameters).
*	params:
*		@r: request_rec object representing current request.
*		@bb: apr_bucket_brigade object that contains the complete html response
*		@place:	the string before which we need to insert text
*		@text: the string that needs to be inserted.
*/
static void insert_text(request_rec *r, apr_bucket_brigade *bb, const char *place,
						const char *text)
{
	
	apr_bucket *b;
	const char *buf;
	const char *tag;
	int sz, flag = 0;
	size_t offset = 0;
	
	
														
	/* loop through the bucket brigade and read each bucekt to scan for the
	*	string place
	*/
	for (b = APR_BRIGADE_FIRST(bb) ;
		 b != APR_BRIGADE_SENTINEL(bb) ;
		 b = APR_BUCKET_NEXT(b) ) {
		 if (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_FLUSH(b))
		 	continue;
		 else {
		apr_bucket_read(b, &buf, &sz, APR_BLOCK_READ);
		if (buf == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_hoverin: buf = NULL");
			return;
		}
		
		/* check if the buffer contains place,
		*  ap_strcasestr will return the pointer to the starting of place
		*  if it finds it, else NULL.
		*/
		tag = ap_strcasestr(buf, place);
		if (tag != NULL) {
						
			/*	calculate the position (offset) where to split the bucket-
			*	We want to split the bucket at the point where place starts in
			*	the bucket, so we find the difference between the starting
			*	address of the buffer (buf) and starting address of place 
			*	(tag),that will be the offset of place within the bucket
			*/
			offset = ((unsigned int) tag - (unsigned int) buf )/sizeof(char) ;
			
			/*  split the bucket at the calculated offset.
			*	The current bucket will be broken down into 2 buckets,
			*	the first bucket will contain data upto the point of offset,
			*	rest of data will be in the next (newly created) bucket.
			*/
			apr_bucket_split(b, offset);
			
			/*	after the split the first bucket will contain data before
			* 	place and the next bucket will containg data starting from
			*	place and onwards. So we will move to the NEXT bucket,
			*	and insert a new bucket (that contains the text) before it.
			*/ 
			b = APR_BUCKET_NEXT(b);
			APR_BUCKET_INSERT_BEFORE(b,
				  					 apr_bucket_heap_create(
				  					 (const char *)text, strlen(text),
				  					 NULL,
				  					 r->connection->bucket_alloc ));
			
			/* 	Increment the flag, so that we may know that place was found
			*	and we can break out from the loop 
			*/
			flag++;
		}
		}
		if (flag) {
			return;
		}
	}
}

/**
	Function to add current url as a comment before the closing head tag
	in the response.
*/
static void add_comment(request_rec *r, apr_bucket_brigade *bb)
{
	/* construct the url */
	const char *url =(const char *) ap_construct_url(r->pool, 
													 (const char *) r->uri, r);
	
	/* build the comment by concatenating the url and the comment syntax */
	const char *my_comment = (const char *) apr_pstrcat(r->connection->pool, 
							"<!-- ", url, " -->", NULL);
	
	/** the place where comment is to be inserted */
	const char *place = (const char *) apr_psprintf(r->connection->pool,
													 "</head>");
																
	/** insert the comment before the </head> */
	insert_text(r, bb, place, my_comment);
}

/**
	Function to generate the javascript variable HOVER to be inserted in the
	HEADER.
*/
static void modify_header(request_rec *r, apr_bucket_brigade *bb)
{
	apr_uri_t *uri = &(r->parsed_uri);
	const char *host = (const char *) r->hostname;
	char *event = ap_getword(r->pool, (const char **) &host, '.');
	
	const char *path = uri->path;
	path++;
	
	const char *url, *referrer, *site, *theme, *hid, *category;
	const char *part, *type, *nick, *hoverlet, *param1;
	
	const char *params = (const char *) apr_psprintf(r->pool, " ");
	int i = 0, j = 0, part_count;
	apr_hash_t *parsed_path = apr_hash_make(r->pool);
	while (*path && (part = ap_getword(r->pool, &path, '/'))) {
		apr_hash_set(parsed_path, &i, sizeof(i), part);
		i++;
	}
	/**
		save the number of entries in the hash table for future use
	*/
	part_count = i;
	i = 0;
	/**
		get the various field values from the hash table into some local 
		variables, only for code conciseness as we need to concatenate these
		values with a very large string.
	*/
	type = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	nick = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	hoverlet = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	param1 = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	
	/**
		Now the only values left in the hash table are from the param field
		that are to be extracted and put in JSON format, so loop through the hash.
	*/
	while ( i < part_count ) {
		if (j) {
			params = (const char *) apr_pstrcat(r->pool, params, ", ", NULL);
		}
		params = (const char *) apr_pstrcat(r->pool, params, 
									apr_psprintf(r->pool, "\'%s\' : \'%s\'",
									apr_itoa(r->pool, ++j),
									apr_hash_get(parsed_path, &i, sizeof(i))), 
									NULL);
		i++;
	}
	
	/**
	*	Extract the rest of the field values from request parameters
	*/

	url = get_parameter(r, "url");
	site = get_parameter(r, "site");
	referrer = get_parameter(r, "ref");
	theme = get_parameter(r, "theme");
	hid = get_parameter(r, "hid");
	category = get_parameter(r, "cat");


	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "theme = %s", theme);
	
	/**
		Now put all the filed values inside the HOVER variable.
	*/
	const char *hover = (const char *)apr_pstrcat(r->pool,
		"var HOVER = { event:\'", event, "\' kw: window.decodeURIComponent(\'", 
		param1, "\')site:\'", site, "\', URL:\'", url, "\', referrer:\'", 
		referrer, "\', nick:\'", nick, "\',category:\'", category, "\', ", 
		"theme:\'", theme, "\', ",  
		"hid:\'", hid, "\', params:{", params, "}};\n", NULL);


	
	const char *place = (const char *) apr_psprintf(r->pool,
						"(function(){HI.Client.Content");
	
	insert_text(r, bb, place, hover);
}


/* per directory configuration initialisation function called by Apache
*	to initialise configuration vectors of the module
*/
static void* hoverin_dir_config(apr_pool_t *pool, char *val)
{
	hoverin_dir_cfg *config = apr_pcalloc(pool, sizeof(hoverin_dir_cfg));
	config->hosts = apr_table_make(pool, 10);
	return config;
}

static void* hoverin_dir_merge(apr_pool_t *pool, void *old, void *new)
{
	hoverin_dir_cfg *o = (hoverin_dir_cfg *) old;
	hoverin_dir_cfg *n = (hoverin_dir_cfg *) new;
	hoverin_dir_cfg *config = apr_palloc(pool, sizeof(hoverin_dir_cfg));
	config->header = o->header ? o->header : n->header;
	config->footer = o->footer ? o->footer : n->footer;
	config->hosts =  o->hosts ? o->hosts : n->hosts;
	return (void *) config;
}


/* filter initialization function */
static int hoverin_filter_init(ap_filter_t *f)
{
	hoverin_ctx *ctx = f->ctx = apr_palloc(f->r->pool, sizeof(hoverin_ctx));
	hoverin_dir_cfg *conf = ap_get_module_config(f->r->per_dir_config,
												 &hoverin_module);
	
	ctx->head = hoverin_file_bucket(f->r, conf->header);
	ctx->foot = hoverin_file_bucket(f->r, conf->footer);
	ctx->hosts = conf->hosts;
	return OK;
}

/* the main filter callback funtion */
static int hoverin_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket *b;
	const char *current_host = f->r->hostname;
	int count = 0;
	apr_off_t length;
	//ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "count = %d", count++);
	apr_table_unset(f->r->headers_out, "Content-Length");
	hoverin_ctx *ctx = (hoverin_ctx *) f->ctx;
	if (ctx == NULL) {
		hoverin_filter_init(f);
		ctx = (hoverin_ctx *) f->ctx;
	}
	
	/** Check if the module should work for this host or not */												 
	if (apr_table_get(ctx->hosts, current_host) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "mod_hoverin: "
						"Invalid host: %s", current_host);
		return ap_pass_brigade(f->next, bb);
		
	}
	parse_query(f->r);
	/*	Insert the footer at the end of the brigade. */
	if ( ctx->foot && ! ( ctx->state & TXT_FOOT ) ) {
			b = APR_BRIGADE_LAST(bb) ;
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "mod_hoverin: " 
						  "setting footer");
			APR_BUCKET_INSERT_BEFORE(b, ctx->foot);
			ctx->state |= TXT_FOOT;
			}
	
	/* Insert the header at the head of the brigade */
	if ( ctx->head && ! ( ctx->state & TXT_HEAD ) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "mod_hoverin: "
					  "setting header");
		APR_BRIGADE_INSERT_HEAD(bb, ctx->head);
		ctx->state |= TXT_HEAD;
	}
	
	/* Header and Footer added to the response, now add the comment */
	//if (count == 0) {

	/*apr_table_t *params_table = ap_get_module_config(f->r->request_config,
										&hoverin_module);*/
	r_cfg *my_r_cfg = ap_get_module_config(f->r->request_config, &hoverin_module);
	apr_table_t *params_table = my_r_cfg->params_table;
	if (params_table == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "parsing query");
		//parse_query(f->r);
		parse_get_params(f->r, f->r->parsed_uri.query);
		add_comment(f->r, bb);
		modify_header(f->r, bb);
	//}
	}
	count++;
	apr_brigade_length(bb, 1, &length);
	apr_table_set(f->r->headers_out, "Content-Length", (const char *) apr_itoa(f->r->pool, length));

	return ap_pass_brigade(f->next, bb);
	//return OK;
}

static const char *set_allowed_hosts(cmd_parms *parms, void *dummy, 
									const char *arg)
{
	hoverin_dir_cfg *config = dummy;
	apr_table_add(config->hosts, arg, (const char *)"A");
	return NULL;
}


/* following is the regular Apache Module stuff, the rudimentary functions 
*	required (in every filter module) to configure the module,
*	setting callbacks, etc 
*/

static const command_rec hoverin_cmds[] = {
	AP_INIT_TAKE1("mod_hoverin_header", ap_set_file_slot,
				  (void *) APR_OFFSETOF(hoverin_dir_cfg, header), OR_ALL,
				   "Header File"),
	AP_INIT_TAKE1("mod_hoverin_footer", ap_set_file_slot, 
				  (void *) APR_OFFSETOF(hoverin_dir_cfg, footer), OR_ALL, 
				  "Footer File"),
	AP_INIT_ITERATE("mod_hoverin_hosts", set_allowed_hosts, NULL, OR_ALL,
					"A list of hosts on which this module listens" ),
	{ NULL }
};

/* setting the hooks */
static void hoverin_hooks(apr_pool_t *pool)
{
	//ap_hook_post_read_request(parse_query, NULL, NULL, APR_HOOK_FIRST);
	//ap_register_output_filter(name, hoverin_filter, hoverin_filter_init, AP_FTYPE_RESOURCE);
	ap_register_output_filter_protocol(name, hoverin_filter,
			hoverin_filter_init, AP_FTYPE_RESOURCE,
			AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH) ;
	  //ap_hook_post_config(line_edit, NULL, NULL, APR_HOOK_MIDDLE) ;
}

/* the module data structure */
module AP_MODULE_DECLARE_DATA hoverin_module = {

	STANDARD20_MODULE_STUFF,
	hoverin_dir_config,
	hoverin_dir_merge,
	NULL,
	NULL,
	hoverin_cmds,
	hoverin_hooks
};


	

	
