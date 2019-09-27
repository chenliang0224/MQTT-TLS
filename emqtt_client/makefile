#CC=mipsel-openwrt-linux-uclibc-gcc
CC=gcc

OBJ=Emqtt_client
all:$(OBJ)

HERE=./

SRC_INC=$(HERE)/src/
POLARSSL_INC=$(HERE)/lib/mbedtls-1.3.14/include/

incs=-I$(HERE)  
incs+=-I$(SRC_INC)
incs+=-I$(POLARSSL_INC)

POLARSSL_LIB_DIR=$(HERE)/lib/mbedtls-1.3.14/library/
SRC_DIR=$(HERE)/src/
#files:=$(HERE)/src/main.c
#files+=$(HERE)/src/MqttSslClient.c
#files+=$(HERE)/src/emqtt.c
files:=$(foreach dir,$(SRC_DIR),$(wildcard $(SRC_DIR)/*.c))
files+=$(foreach dir,$(POLARSSL_LIB_DIR),$(wildcard $(POLARSSL_LIB_DIR)/*.c))

OBJS_C := $(patsubst %.c,%.o,$(files))

CFLAGS=-O0 -g 
CFLAGS+=$(incs) 

LDFLAGS=-lpthread 

$(OBJ):$(OBJS_C)
	$(CC)  $(LDFLAGS) -o $@ $^ 
			
$(OBJS_C):%.o:%.c
	$(CC) $(CFLAGS)  -c $< -o $@

clean:
	rm -rf $(SRC_INC)/*.o
	rm -rf $(POLARSSL_LIB_DIR)/*.o
	rm -rf $(HERE)/$(OBJ)

