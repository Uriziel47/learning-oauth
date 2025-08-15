create user keycloak with password 'changeit';
create database keycloak;
grant all privileges on database keycloak to keycloak;
\c keycloak
grant all privileges on schema keycloak to keycloak;
