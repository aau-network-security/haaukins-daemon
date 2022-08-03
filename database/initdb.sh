#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        CREATE USER $HAAUKINSDB_USER;
        ALTER USER $HAAUKINSDB_USER WITH PASSWORD '$HAAUKINSDB_PASSWORD';
        CREATE DATABASE $HAAUKINSDB_NAME;
        GRANT ALL PRIVILEGES ON DATABASE $HAAUKINSDB_NAME TO $HAAUKINSDB_USER;
EOSQL

PGPASSWORD=$HAAUKINSDB_PASSWORD psql -v ON_ERROR_STOP=1 --username "$HAAUKINSDB_USER" --dbname "$HAAUKINSDB_NAME" <<-EOSQL
        CREATE TABLE IF NOT EXISTS Event ( 
                id serial primary key, 
                tag varchar (255) NOT NULL, 
                name varchar (255) NOT NULL, 
                available integer NOT NULL, 
                capacity integer NOT NULL, 
                status integer, 
                frontends text NOT NULL, 
                exercises text NOT NULL, 
                started_at timestamp NOT NULL,
                finish_expected timestamp NOT NULL, 
                finished_at timestamp NOT NULL, 
                createdBy text NOT NULL, 
                onlyVPN integer, 
                secretKey text NOT NULL, 
                disabledExercises text NOT NULL
        );

        CREATE TABLE IF NOT EXISTS Team (
                id serial primary key,
                tag varchar(255) NOT NULL,
                event_id integer NOT NULL,
                email varchar (255) NOT NULL,
                name varchar (255) NOT NULL, 
                password varchar (255) NOT NULL,
                created_at timestamp NOT NULL,
                last_access timestamp NOT NULL,
                solved_challenges text NOT NULL
        );


        -- Admin related tables
        CREATE TABLE IF NOT EXISTS Organizations (
                id serial primary key,
                name varchar (255) NOT NULL,
                owner_user varchar(255) NOT NULL,
                owner_email varchar(255) NOT NULL,
                UNIQUE(name)
        );
        CREATE UNIQUE INDEX orgname_lower_index ON Organizations (LOWER(name));

        CREATE TABLE IF NOT EXISTS Profiles (
                id serial primary key, 
                name varchar (255) NOT NULL, 
                secret boolean NOT NULL, 
                organization varchar(255) NOT NULL REFERENCES Organizations (name) ON DELETE CASCADE,
                challenges text NOT NULL
        );        
        CREATE UNIQUE INDEX profilename_lower_index ON Profiles (LOWER(name));

        CREATE TABLE IF NOT EXISTS Admin_users (
                id serial primary key, 
                username varchar (255) NOT NULL, 
                password varchar (255) NOT NULL,
                email varchar (255) NOT NULL,
                role varchar (255) NOT NULL,
                organization varchar (255) NOT NULL REFERENCES Organizations (name) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX username_lower_index ON Admin_users (LOWER(username));

        CREATE TABLE IF NOT EXISTS Exercise_dbs (
                id serial primary key,
                name varchar (255) NOT NULL,
                organization varchar (255) NOT NULL REFERENCES Organizations (name) ON DELETE CASCADE, 
                url varchar (255) NOT NULL,
                sign_key varchar (255) NOT NULL,
                auth_key varchar (255) NOT NULL
        );
        CREATE UNIQUE INDEX exdbname_lower_index ON Exercise_dbs (LOWER(name));

        CREATE TABLE IF NOT EXISTS Haaukins_agents (
                id serial primary key,
                name varchar (255) NOT NULL,
                url varchar (255) NOT NULL,
                sign_key varchar (255) NOT NULL,
                auth_key varchar (255) NOT NULL
        );
        CREATE UNIQUE INDEX agentname_lower_index ON Haaukins_agents (LOWER(name));

        CREATE TABLE IF NOT EXISTS Frontends (
                id serial primary key, 
                name varchar (255) NOT NULL,
                image varchar (255) NOT NULL,
                memoryMB integer
        );
        CREATE UNIQUE INDEX frontendname_lower_index ON Frontends (LOWER(name));



        -- Setting up an administrative account with password admin
        INSERT INTO Organizations (name, owner_user, owner_email) VALUES ('org::Admins', 'admin', 'cyber@es.aau.dk');
        INSERT INTO Admin_users (username, password, email, role, organization) VALUES ('admin', '\$2a\$10\$uwUoW.w5OZKEa5/UJrYyM.fz9vjH3z1sGsZWXZ2Nmf0obL9OK80kC', 'cyber@es.aau.dk', 'role::superadmin', 'org::Admins');
        
EOSQL