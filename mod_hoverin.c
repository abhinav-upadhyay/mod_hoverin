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

/* filter context data structure f->ctx */
typedef struct {
	apr_bucket *head;
	apr_bucket *foot;
	apr_table_t *hosts;
	unsigned int state;
} hoverin_ctx;



/* Name of the filter-module */
static const char *name = "hoverin-filter";

#define TXT_HEAD 0x01
#define TXT_FOOT 0x02

/* a utility function that reads the header and footer files and returns them 
*	in the form of a file bucket
*	params:
*		@r a request_rec object that represents the current request_rec
*		@fname the name of the file that needs to be read
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

/** insert_text function scans the passed in brigade bb for the closing head tag,
*	if it finds the closing head tag (</head>) it will attach the current URL in
*	the form of	a comment before the closing head tag (</head>)
*	params:
*		@r: request_rec object representing current request.
*		@bb; apr_bucket_brigade object that contains the complete html response
*/
static void insert_text(request_rec *r, apr_bucket_brigade *bb, char *place,
						const char *text)
{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "in insert_text");
	apr_bucket *b;
	const char *buf;
	const char *tag;
	int sz, flag = 0;
	size_t offset = 0;
	
	
														
	/* loop through the bucket brigade and read each bucekt to scan for the
	*	closing head tag </head>
	*/
	for (b = APR_BRIGADE_FIRST(bb) ;
		 b != APR_BRIGADE_SENTINEL(bb) ;
		 b = APR_BUCKET_NEXT(b) ) {
		 ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "reading buf");
		apr_bucket_read(b, &buf, &sz, APR_BLOCK_READ);
		if (buf == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_hoverin: buf = NULL");
			return;
		}
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "buf read");
		/* check if the buffer contains </head>,
		*  ap_strcasestr will return the pointer to the starting of </head>
		*  if it finds it else NULL.
		*/
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "reading tag");
		tag = ap_strcasestr(buf, place);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "tag read");
		if (tag != NULL) {
						
			/*	calculate the position (offset) where to split the bucket-
			*	We want to split the bucket at the point where </head> starts in
			*	the bucket, so we find the difference between the starting
			*	address of the buffer (buf) and starting address of </head> tag
			*	(tag),that will be the offset of </head>, within the bucket
			*/
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "calculating offset");
			offset = ((unsigned int) tag - (unsigned int) buf )/sizeof(char) ;
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "offset calculated");			
			/*  split the bucket at the calculated offset.
			*	The current bucket will be broken down into 2 buckets,
			*	the first bucket will contain data upto the point of offset,
			*	rest of data will be in the next (newly created) bucket.
			*/
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "splitting the bucket");
			apr_bucket_split(b, offset);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "bucket splitted");			
			/*	after the split the first bucket will contain data before
			* 	</head> and	the next bucket will containg data starting from
			*	</head> and onwards. So we will move to the NEXT bucket,
			*	and insert a new bucket (that contains the comment) before it.
			*/ 
			b = APR_BUCKET_NEXT(b);
			APR_BUCKET_INSERT_BEFORE(b,
				  					 apr_bucket_transient_create(
				  					 (const char *)text, strlen(text),
				  					 r->connection->bucket_alloc ));
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "text inserted");
			/* 	Increment the flag, so that we may know that </head> tag was found
			*	and we can break out from the loop 
			*/
			flag++;
		}
		if (flag) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "flag is positive");
			return;
		}
	}
}


static void add_comment(request_rec *r, apr_bucket_brigade *bb)
{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "In add_comment");
	/* construct the url */
	const char *url =(const char *) ap_construct_url(r->pool, 
													 (const char *) r->uri, r);
	
	/* build the comment by concatenating the url and the comment syntax */
	const char *my_comment = (const char *) apr_pstrcat(r->pool, "<!-- ", url,
														" -->", NULL);
	
	/** the place where comment is to be inserted */
	char *place = "</head>";
	apr_pool_cleanup_register(r->pool, (const void *)place, (void *)free, NULL);
	//char *place = apr_psprintf(r->pool, "x");
														
	/** insert the comment before the </head> */
	insert_text(r, bb, place, my_comment);
}

static void modify_header(request_rec *r, apr_bucket_brigade *bb)
{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "In modify_header");
	apr_uri_t *uri = &(r->parsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "apr_uri_t");
//	const char *host = (const char *) uri->hostname;
	const char *host = "onhover.localhost";
	char *event = ap_getword(r->pool, (const char **) &host, '.');
	
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", event);
	const char *path = uri->path;
	const char *part, *type, *nick, *hoverlet, *param1;
	//char *hover = "var HOVER = { ";
	int i = 0, j;
	apr_hash_t *parsed_path = apr_hash_make(r->pool);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "setting parsed_path");
	while (*path && (part = ap_getword(r->pool, &path, '/'))){
		apr_hash_set(parsed_path, &i, sizeof(i), part);
		i++;
	
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "parsed_path set");
	i = 0;
	type = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	nick = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	hoverlet = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	param1 = apr_hash_get(parsed_path, &i, sizeof(i));
	i++;
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "values taken from hash %s %s %s %s", type, nick, hoverlet, param1);
	const char *hover = (const char *)apr_pstrcat(r->pool, "var HOVER = { event:\'", event, 
	 "\' kw: window.decodeURIComponent(\'", param1, "\')site:\'\', URL:\'\'", 
	 ", referrer:\'\', nick:\'", nick, "\',category:\'\', ", 
	 "theme:\'http://themes.v2.hoverin.s3.amazonaws.com/hi-ap.css\', hid:\'8\', ", 
	 "params:{}};", NULL);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "hover made");
	insert_text(r, bb, "</head>", hover);
	
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
	add_comment(f->r, bb);
	//modify_header(f->r, bb);
	return ap_pass_brigade(f->next, bb);
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
	ap_register_output_filter(name, hoverin_filter, hoverin_filter_init, AP_FTYPE_RESOURCE);
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


	

	
