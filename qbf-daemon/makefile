HASHMAPDIR=c-hashmap/
SOURCEDIR=src/
TESTINCLUDES=-Iinclude/
INCLUDES=$(TESTINCLUDES) -I$(HASHMAPDIR)
SOURCES=$(SOURCEDIR)resource_record.c $(SOURCEDIR)question.c \
	 $(SOURCEDIR)dns_message.c $(HASHMAPDIR)map.c

daemon: $(SOURCEDIR)daemon.c $(HASHMAPDIR)map.c $(SOURCES)
	$(CC) -o $@ -Wall -pedantic -g $^ -lnetfilter_queue -lrt -lm $(INCLUDES) -pthread
