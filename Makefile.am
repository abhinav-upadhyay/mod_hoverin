## Define compiler debug flags
AM_CFLAGS = $(CXXDEBUGDEFINES)

## Define the source file for the module
noinst_SCRIPTS = mod_hoverin.so
DIST_SOURCES = mod_hoverin.c

mod_hoverin.so:
	$(APXS) $(APXS_CXX_OPTIONS) $(INCLUDES) -c mod_hoverin.c

## Define install targets
install: mod_hoverin.so
	$(APXS) -i -a mod_hoverin.la
	@if [ "$(WGET)" = "wget" ]; \
		then \
		if [ wget  http://start.hover.in/mod_hoverin/1/header.html http://start.hover.in/mod_hoverin/1/footer.html 2>/dev/null ]; \
			then \
			echo "header.html and footer.html downloaded successfully"; \
		else \
			echo "Could not find header.html and footer.html on the provided URl, please contact someone at http://hover.in to get the file"; \
		fi ; \
	elif [ "$(WGET)" = "curl" ]; \
		then \
		if [ curl -O http://start.hover.in/mod_hoverin/1/header.html  http://start.hover.in/mod_hoverin/1/footer.html 2>/dev/null ]; \
			then \
			echo "header.html and footer.html downloaded successfully"; \
		else \
			echo "Could not find header.html and footer.html on the provided URl, please contact someone at http://hover.in to get the file "; \
		fi ; \
	else \
		printf "Could not download header.html and footer.html ";  \
		printf	"because wget or curl was not found installed on your system. Please install either of the two (wget or curl) and try again "; \	
		printf	"or you can manually download the files yourself from the following URLs \n\n"; \
		printf	"http://start.hover.in/mod_hoverin/1/header.html \n"; \
		printf	"http://start.hover.in/mod_hoverin/1/footer.html \n\n"; \
		printf	"Just open the pages in your browser and save them on your local disk \n" ;\
	fi
	
	@printf "\n-------------------------------------------------------------------------\n"; \
	printf  "YOU NEED TO SETUP FOLLOWING DIRECTIVES FOR CONFIGURING THIS MODULE\n";\
	printf  "\n";\
	printf  "<VirtualHost 56.64.112.10>\n";\
	printf	"#the root directory with respect to which documents are served.\n";\
	printf	"DocumentRoot /usr/local/apache2/htdocs/\n";\
	printf	"#host name\n";\
	printf	"ServerName onhover.%s\n" $(SITE);\
	printf	"#mod_hoverin's directives\n";\
	printf	"AddOutputFilterByType hoverin-filter text/html text/plain\n";\
	printf	"Header \"/usr/local/apache2/htdocs/hoverin/header.html\"\n";\
	printf	"Footer \"/usr/local/apache2/htdocs/hoverin/footer.html\"\n";\
	printf	"</VirtualHost>\n";\
	printf	"\n";\
	printf	"NOTE: Replace 56.64.112.10 with your server's IP address. \n";\
	printf	"You should have a DNS record that points your subdomain to your server's IP address. \n";\
	printf  "\n-------------------------------------------------------------------------\n" ;\
	printf "Please read the README file for more help and reference.\nThanks\n"

	 		 
	 		 
