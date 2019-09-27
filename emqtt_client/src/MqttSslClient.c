#include <poll.h>
#include "MqttSslClient.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"
#include "polarssl/sha256.h"
#include "string.h"

#if 1
const char cert_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDPzCCAiegAwIBAgIBBDANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MTEwMjEyMTQ0NDA3WhcNMjEwMjEyMTQ0NDA3WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UEChMIUG9sYXJTU0wxGjAYBgNVBAMTEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6f\r\n"
"M60Nj4o8VmXl3ETZzGaFB9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu\r\n"
"1C93KYRhTYJQj6eVSHD1bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEw\r\n"
"MjDV0/YI0FZPRo7yX/k9Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v\r\n"
"4Jv4EFbMs44TFeY0BGbH7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx/\r\n"
"/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB\r\n"
"o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBRxoQBzckAvVHZeM/xSj7zx3WtGITAf\r\n"
"BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQUFAAOC\r\n"
"AQEAAn86isAM8X+mVwJqeItt6E9slhEQbAofyk+diH1Lh8Y9iLlWQSKbw/UXYjx5\r\n"
"LLPZcniovxIcARC/BjyZR9g3UwTHNGNm+rwrqa15viuNOFBchykX/Orsk02EH7NR\r\n"
"Alw5WLPorYjED6cdVQgBl9ot93HdJogRiXCxErM7NC8/eP511mjq+uLDjLKH8ZPQ\r\n"
"8I4ekHJnroLsDkIwXKGIsvIBHQy2ac/NwHLCQOK6mfum1pRx52V4Utu5dLLjD5bM\r\n"
"xOBC7KU4xZKuMXXZM6/93Yb51K/J4ahf1TxJlTWXtnzDr9saEYdNy2SKY/6ZiDNH\r\n"
"D+stpAKiQLAWaAusIWKYEyw9MQ==\r\n"
"-----END CERTIFICATE-----\r\n";

const char cli_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6fM60Nj4o8VmXl3ETZzGaF\r\n"
"B9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu1C93KYRhTYJQj6eVSHD1\r\n"
"bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEwMjDV0/YI0FZPRo7yX/k9\r\n"
"Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v4Jv4EFbMs44TFeY0BGbH\r\n"
"7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx//DZrtenNLQNiTrM9AM+v\r\n"
"dqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQABAoIBAGdNtfYDiap6bzst\r\n"
"yhCiI8m9TtrhZw4MisaEaN/ll3XSjaOG2dvV6xMZCMV+5TeXDHOAZnY18Yi18vzz\r\n"
"4Ut2TnNFzizCECYNaA2fST3WgInnxUkV3YXAyP6CNxJaCmv2aA0yFr2kFVSeaKGt\r\n"
"ymvljNp2NVkvm7Th8fBQBO7I7AXhz43k0mR7XmPgewe8ApZOG3hstkOaMvbWAvWA\r\n"
"zCZupdDjZYjOJqlA4eEA4H8/w7F83r5CugeBE8LgEREjLPiyejrU5H1fubEY+h0d\r\n"
"l5HZBJ68ybTXfQ5U9o/QKA3dd0toBEhhdRUDGzWtjvwkEQfqF1reGWj/tod/gCpf\r\n"
"DFi6X0ECgYEA4wOv/pjSC3ty6TuOvKX2rOUiBrLXXv2JSxZnMoMiWI5ipLQt+RYT\r\n"
"VPafL/m7Dn6MbwjayOkcZhBwk5CNz5A6Q4lJ64Mq/lqHznRCQQ2Mc1G8eyDF/fYL\r\n"
"Ze2pLvwP9VD5jTc2miDfw+MnvJhywRRLcemDFP8k4hQVtm8PMp3ZmNECgYEA4gz7\r\n"
"wzObR4gn8ibe617uQPZjWzUj9dUHYd+in1gwBCIrtNnaRn9I9U/Q6tegRYpii4ys\r\n"
"c176NmU+umy6XmuSKV5qD9bSpZWG2nLFnslrN15Lm3fhZxoeMNhBaEDTnLT26yoi\r\n"
"33gp0mSSWy94ZEqipms+ULF6sY1ZtFW6tpGFoy8CgYAQHhnnvJflIs2ky4q10B60\r\n"
"ZcxFp3rtDpkp0JxhFLhiizFrujMtZSjYNm5U7KkgPVHhLELEUvCmOnKTt4ap/vZ0\r\n"
"BxJNe1GZH3pW6SAvGDQpl9sG7uu/vTFP+lCxukmzxB0DrrDcvorEkKMom7ZCCRvW\r\n"
"KZsZ6YeH2Z81BauRj218kQKBgQCUV/DgKP2985xDTT79N08jUo3hTP5MVYCCuj/+\r\n"
"UeEw1TvZcx3LJby7P6Xad6a1/BqveaGyFKIfEFIaBUBItk801sDDpDaYc4gL00Xc\r\n"
"7lFuBHOZkxJYlss5QrGpuOEl9ZwUt5IrFLBdYaKqNHzNVC1pCPfb/JyH6Dr2HUxq\r\n"
"gxUwAQKBgQCcU6G2L8AG9d9c0UpOyL1tMvFe5Ttw0KjlQVdsh1MP6yigYo9DYuwu\r\n"
"bHFVW2r0dBTqegP2/KTOxKzaHfC1qf0RGDsUoJCNJrd1cwoCLG8P2EF4w3OBrKqv\r\n"
"8u4ytY0F+Vlanj5lm3TaoHSVF1+NWPyOTiwevIECGKwSxvlki4fDAA==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";


#define CA_CRT_RSA                                                 \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIDhzCCAm+gAwIBAgIBADANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"  \
"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"  \
"MTEwMjEyMTQ0NDAwWhcNMjEwMjEyMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n"  \
"A1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n"  \
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n"  \
"mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n"  \
"50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n"  \
"YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n"  \
"R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n"  \
"KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n"  \
"gZUwgZIwDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUtFrkpbPe0lL2udWmlQ/rPrzH\r\n"  \
"/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV\r\n"  \
"BAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEZMBcGA1UEAxMQUG9sYXJTU0wgVGVz\r\n"  \
"dCBDQYIBADANBgkqhkiG9w0BAQUFAAOCAQEAuP1U2ABUkIslsCfdlc2i94QHHYeJ\r\n"  \
"SsR4EdgHtdciUI5I62J6Mom+Y0dT/7a+8S6MVMCZP6C5NyNyXw1GWY/YR82XTJ8H\r\n"  \
"DBJiCTok5DbZ6SzaONBzdWHXwWwmi5vg1dxn7YxrM9d0IjxM27WNKs4sDQhZBQkF\r\n"  \
"pjmfs2cb4oPl4Y9T9meTx/lvdkRYEug61Jfn6cA+qHpyPYdTH+UshITnmp5/Ztkf\r\n"  \
"m/UTSLBNFNHesiTZeH31NcxYGdHSme9Nc/gfidRa0FLOCfWxRlFqAI47zG9jAQCZ\r\n"  \
"7Z2mCGDNMhjQc+BYcdnl0lPXjdDK6V0qCg1dVewhUBcW5gZKzV7e9+DpVA==\r\n"      \
"-----END CERTIFICATE-----\r\n"
const char ca_list[] = CA_CRT_RSA;
#endif

entropy_context entropy;
ctr_drbg_context ctr_drbg;
ssl_context ssl;
x509_crt cacert;
x509_crt clicert;
pk_context pkey;
int MqttSslClientFd = -1;

/*处理云端推送消息*/
void MqttSslDealPublishMsg(const uint8 *buf)
{
    //deal topic
    const uint8* topic_ptr = NULL;
	uint16 topic_len = mqtt_parse_pub_topic_ptr(buf, &topic_ptr);
    if (topic_len <= 0) {
        DEBUG_INFO("topic len = 0");
        return;
    }
    uint8* topic = malloc(topic_len*sizeof(uint8));
    if (NULL == topic) {
        DEBUG_INFO("malloc failed topic");
        goto DEAL_MSG_EXIT;
    }
    mqtt_parse_pub_topic(buf,topic);
    DEBUG_INFO("topic:%s",topic);

    //deal msg
    uint8 *msg_ptr = NULL;
    uint16 msg_len = mqtt_parse_pub_msg_ptr(buf,&msg_ptr);
    if (msg_len <= 0) {
        DEBUG_INFO("msg len = 0");
        goto DEAL_MSG_EXIT;
    }
    uint8* msg = malloc(msg_len*sizeof(uint8));
    if (NULL == msg) {
        DEBUG_INFO("malloc failed msg");
        goto DEAL_MSG_EXIT;
    }
    mqtt_parse_publish_msg(buf,msg);
    DEBUG_INFO("msg:%s",msg);
    
DEAL_MSG_EXIT:  
    if (msg != NULL) {
        free(msg);
    }
    if (topic != NULL) {
        free(topic);
    }
}

/*mqtt消息类型解析*/
void ReadMqttSslData(ssl_context *ssl)
{
    uint8 buf[8192] = {0};
    int len = sizeof(buf) - 1;
    int ret = ssl_read(ssl, buf, len);

    //后面要完善错误处理
    if (ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE) {
        return;
    }
    if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return;
    }
    if( ret < 0 ) {
        DEBUG_INFO("failed\n  ! ssl_read returned %d\n\n", ret );
        return;
    }
    if (ret == 0) {
        DEBUG_INFO("\n\nEOF\n\n" );
        return;
    }
    //后面要完善错误处理

   uint8_t MsgType = MQTTParseMessageType(buf) >> 4;
   DEBUG_INFO("%d",MsgType);

   switch (MsgType) {
      case MSG_CONNACK:
        DEBUG_INFO("MSG_CONNACK:%d",MSG_CONNACK);
      break;

      case MSG_PUBLISH:
        DEBUG_INFO("MSG_PUBLISH:%d",MSG_PUBLISH);
        MqttSslDealPublishMsg(buf);
      break;

      case MSG_PUBREL:
        DEBUG_INFO("MSG_PUBREL:%d",MSG_PUBREL);
      break;

      case MSG_SUBSCRIBE:
        DEBUG_INFO("MSG_SUBSCRIBE:%d",MSG_SUBSCRIBE);
      break;

      case MSG_SUBACK:
        DEBUG_INFO("MSG_SUBACK:%d",MSG_SUBACK);
      break;
      
      case MSG_UNSUBSCRIBE:
        DEBUG_INFO("MSG_UNSUBSCRIBE:%d",MSG_UNSUBSCRIBE);
      break;

      case MSG_PINGRESP:
        DEBUG_INFO("MSG_PINGRESP:%d",MSG_PINGRESP);
      break;

      case MSG_DISCONNECT:
        DEBUG_INFO("MSG_DISCONNECT:%d",MSG_DISCONNECT);
      break;
   }
}

/* 测试 */
void *MqttSslClientPoll(void *arg)
{
    struct pollfd pollFd;
    pollFd.fd = MqttSslClientFd;
	pollFd.events = POLLIN;
	while (1) {
		poll(&pollFd, 1, -1);
        if (pollFd.revents) {
		    ReadMqttSslData(&ssl);
		}	
	}	
	return  NULL;
}
 
/* 测试 */
void *MqttSslClientPing(void *arg)
{
	while (1) {
	    mqtt_ping(&TRBroker);
        sleep(3);
	}	
	return  NULL;
}

/* mqtt ssl 初始化失败退出 */
void ExitClear(void)
{
    ssl_close_notify(&ssl);
    net_close(MqttSslClientFd);
    x509_crt_free(&cacert);
    ssl_free(&ssl);
    ctr_drbg_free(&ctr_drbg);
    entropy_free(&entropy);
}

/* mqtt ssl 初始化 */
int MqttSslClientInit(void)
{
    int ret;
    uint32_t flags;
    const char *pers = "mqtt_ssl_client1";
	const char* test = "test publish";	

    //Initialize the RNG and the session data
    ssl_init(&ssl);
    x509_crt_init(&cacert);
    x509_crt_init(&clicert);
    pk_init(&pkey);

    entropy_init(&entropy);
    if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,(const unsigned char*)pers, strlen(pers))) != 0)  {
        DEBUG_INFO( " failed  ! ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    //Initialize certificates
    DEBUG_INFO("  . Loading the CA root certificate ...");
#ifdef SSL_FILE
    ret = x509_crt_parse_file(&cacert, "/usr/sbin/cacert.pem");
    if (ret < 0) {
        DEBUG_INFO("failed  !  x509_crt_parse returned -0x%x\n", -ret );
        goto exit;
    }

	ret = x509_crt_parse_file(&clicert, "/usr/sbin/client.crt");
	if (ret != 0) {
		DEBUG_INFO(" failed  !  x509_crt_parse returned %d\n", ret );
		goto exit;
	}

	ret = pk_parse_keyfile(&pkey, "/usr/sbin/client.key", "123456");
    if (ret != 0) {
        DEBUG_INFO("failed  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }
#else 
     ret = x509_crt_parse(&cacert,(const unsigned char *) ca_list,strlen(ca_list));
     if (ret < 0) {
        DEBUG_INFO("failed  !  x509_crt_parse returned -0x%x\n", -ret );
        goto exit;
     } 

     ret = x509_crt_parse(&clicert, (const unsigned char *)cert_rsa, strlen(cert_rsa));
     if (ret < 0) {
        DEBUG_INFO("failed  !  x509_crt_parse returned -0x%x\n", -ret );
        goto exit;
     }

     ret = pk_parse_key(&pkey,(const unsigned char *)cli_key_rsa, strlen(cli_key_rsa), "hdl1985", 7);
     if (ret != 0) {
        DEBUG_INFO("failed  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }          
#endif
    //Start the connection
    DEBUG_INFO("Connecting to tcp/%s/%d...", SERVER_NAME, SERVER_PORT);
    if ((ret = net_connect(&MqttSslClientFd, SERVER_NAME,SERVER_PORT)) != 0)  {
        DEBUG_INFO(" failed  ! net_connect returned %d\n", ret );
        goto exit;
    }

    //Setup stuff
    DEBUG_INFO("Setting up the SSL/TLS structure...");
    ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    ssl_set_authmode(&ssl, SSL_VERIFY_OPTIONAL);
    ssl_set_ca_chain(&ssl, &cacert, NULL, "PolarSSL Server 1");
    //SSLv3 is deprecated, set minimum to TLS 1.0 
    ssl_set_min_version(&ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1);
    // RC4 is deprecated, disable it 
    ssl_set_arc4_support(&ssl, SSL_ARC4_DISABLED);
    ssl_set_rng(&ssl,ctr_drbg_random, &ctr_drbg);
    //ssl_set_dbg(&ssl, my_debug, stdout);
    ssl_set_bio(&ssl, net_recv, &MqttSslClientFd, net_send, &MqttSslClientFd);
                      
    //Handshake
    DEBUG_INFO("Performing the SSL/TLS handshake...");
    while ((ret = ssl_handshake(&ssl))!= 0) {
        if (ret != POLARSSL_ERR_NET_WANT_READ)  {
            DEBUG_INFO("failed ! ssl_handshake returned -0x%x\n", -ret);
            goto exit;
        }
    }

#if 1  //证书验证
    //Verify the server certificate
    DEBUG_INFO("Verifying peer X.509 certificate...");
    // In real life, we probably want to bail out when ret != 0 
    if ((flags = ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];
        x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags);
        DEBUG_INFO("failed,%s", vrfy_buf );
    }
#endif    

    DEBUG_INFO("mqtttenter");
	PTmqtttenter();
	mqtt_connect((mqtt_broker_handle_t *)PTMqttGetBroker());
    DEBUG_INFO("mqtt_connect");
	mqtt_subscribe((mqtt_broker_handle_t *)PTMqttGetBroker(), MQTTSUBTOPIC, 0);
    mqtt_subscribe((mqtt_broker_handle_t *)PTMqttGetBroker(), MQTTSUBTOPIC1, 0);
	mqtt_publish((mqtt_broker_handle_t *)PTMqttGetBroker(), MQTTPUBTOPIC, test, strlen(test), 0);

   pthread_t MqttPingid;
   pthread_t MqttSslClientId;
   //pthread_create(&MqttPingid, NULL, &MqttSslClientPing,NULL);	
   pthread_create(&MqttSslClientId, NULL, &MqttSslClientPoll,NULL);
    
   while(1)   {
       mqtt_ping((mqtt_broker_handle_t *)PTMqttGetBroker());
       mqtt_publish((mqtt_broker_handle_t *)PTMqttGetBroker(), MQTTPUBTOPIC, test, strlen(test), 0); 
       sleep(30);
   }

exit:
    ExitClear();
    return(ret);     
}


