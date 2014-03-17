NTLM & Kerberos Auth
========

Пример GET запроса c поддержкой NTLMv2 и Kerberos, SSL + JKS 
на java api и apache HttpClient4

Важные моменты:
В секции libdefaults параметр udp_preference_limit - задает ограничение для upd пакетов, помогает при соответсвующей ошибки обмена с kdc сервером.
Параметр forwardable - позволяет использовать krb-tickets в многозвенных решениях.
