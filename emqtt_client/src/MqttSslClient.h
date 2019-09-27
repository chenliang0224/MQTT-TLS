#ifndef _MQTT_SSL_CLIENT_H
#define _MQTT_SSL_CLIENT_H

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"
#include "polarssl/sha256.h"
#include "emqtt.h"

int  MqttSslClientInit(void);
void MqttSslDealPublishMsg(const uint8 *buf);
void ReadMqttSslData(ssl_context *ssl);

#endif
