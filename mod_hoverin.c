#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <util_filter.h>
#include <http_config.h>
#include <apr_strmatch.h>
/* All function names starting with hoverin : like a namespace */
module AP_MODULE_DECLARE_DATA hoverin_module  ;

/* per-dir-configuration data structure for the module */
typedef struct {
	const char *header;
	const char *footer;
} hoverin_dir_cfg;

/* filter context data structure f->ctx */
typedef struct {
	apr_bucket *head;
	apr_bucket *foot;
	unsigned int state;
} hoverin_ctx;

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

/*  add_comment function scans the passed in brigade bb for the closing head tag,
*	if it finds the closing head tag (</head>) it will attach the current URL in
*	the form of	a comment before the closing head tag (</head>)
*	params:
*		@r: request_rec object representing current request.
*		@bb; apr_bucket_brigade object that contains the complete html response
*/
static void add_comment(request_rec *r, apr_bucket_brigade *bb)
{
	apr_bucket *b;
	const char *buf;
	const char *tag;
	int sz, flag = 0;
	size_t offset = 0;
	
	/* construct the url */
	const char *url =(const char *) ap_construct_url(r->pool, 
													 (const char *) r->uri, r);
	
	/* build the comment by concatenating the url and the comment syntax */
	const char *my_comment = (const char *) apr_pstrcat(r->pool, "<!-- ", url,
														" -->", NULL);
														
	/* loop through the bucket brigade and read each bucekt to scan for the
	*	closing head tag </head>
	*/
	for (b = APR_BRIGADE_FIRST(bb) ;
		 b != APR_BRIGADE_SENTINEL(bb) ;
		 b = APR_BUCKET_NEXT(b) ) {
		apr_bucket_read(b, &buf, &sz, APR_BLOCK_READ);
		if (buf == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_hoverin: buf = NULL");
			return;
		}
		/* check if the buffer contains </head>,
		*  ap_strcasestr will return the pointer to the starting of </head>
		*  if it finds it else NULL.
		*/
		tag = ap_strcasestr(buf, "</head>");
		if (tag != NULL) {
						
			/*	calculate the position (offset) where to split the bucket-
			*	We want to split the bucket at the point where </head> starts in
			*	the bucket, so we find the difference between the starting
			*	address of the buffer (buf) and starting address of </head> tag
			*	(tag),that will be the offset of </head>, within the bucket
			*/
			offset = ((unsigned int) tag - (unsigned int) buf )/sizeof(char) ;
						
			/*  split the bucket at the calculated offset.
			*	The current bucket will be broken down into 2 buckets,
			*	the first bucket will contain data upto the point of offset,
			*	rest of data will be in the next (newly created) bucket.
			*/
			apr_bucket_split(b, offset);
						
			/*	after the split the first bucket will contain data before
			* 	</head> and	the next bucket will containg data starting from
			*	</head> and onwards. So we will move to the NEXT bucket,
			*	and insert a new bucket (that contains the comment) before it.
			*/ 
			b = APR_BUCKET_NEXT(b);
			APR_BUCKET_INSERT_BEFORE(b,
				  					 apr_bucket_transient_create(
				  					 (const char *)my_comment, strlen(my_comment),
				  					 r->connection->bucket_alloc ));
			/* 	Increment the flag, so that we may know that </head> tag was found
			*	and we can break out from the loop 
			*/
			flag++;
		}
		if (flag) {
			return;
		}
	}
}


/* per directory configuration initialisation function called by Apache
*	to initialise configuration vectors of the module
*/
static void* hoverin_dir_config(apr_pool_t *pool, char *val)
{
	return (apr_pcalloc(pool, sizeof(hoverin_dir_cfg)));
}

static void* hoverin_dir_merge(apr_pool_t *pool, void *old, void *new)
{
	hoverin_dir_cfg *o = (hoverin_dir_cfg *) old;
	hoverin_dir_cfg *n = (hoverin_dir_cfg *) new;
	hoverin_dir_cfg *config = apr_palloc(pool, sizeof(hoverin_dir_cfg));
	config->header = o->header ? o->header : n->header;
	config->footer = n->footer ? n->footer : n->footer;
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
	return OK;
}

/* the main filter callback funtion */
static int hoverin_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket *b;
	hoverin_ctx *ctx = (hoverin_ctx *) f->ctx;
	if (ctx == NULL) {
		hoverin_filter_init(f);
		ctx = (hoverin_ctx *) f->ctx;
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
	return ap_pass_brigade(f->next, bb);
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


	

	
