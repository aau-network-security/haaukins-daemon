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
                tag varchar (50), 
                name varchar (150), 
                available integer, 
                capacity integer, 
                status integer, 
                frontends text, 
                exercises text, 
                started_at timestamp, 
                finish_expected timestamp, 
                finished_at timestamp, 
                createdBy text, 
                onlyVPN integer, 
                secretKey text, 
                disabledExercises text
        );

        CREATE TABLE IF NOT EXISTS Team (
                id serial primary key,
                tag varchar(50),
                event_id integer,
                email varchar (50),
                name varchar (50), 
                password varchar (250),
                created_at timestamp,
                last_access timestamp,
                solved_challenges text
        );

        CREATE TABLE IF NOT EXISTS Organizations (
                id serial primary key,
                name varchar (50)
        );

        CREATE TABLE IF NOT EXISTS Profiles (
                id serial primary key, 
                name varchar (50), 
                secret boolean, 
                organization_id integer REFERENCES Organizations (id) ON DELETE CASCADE,
                challenges text
        );        

        CREATE TABLE IF NOT EXISTS Admin_users (
                id serial primary key, 
                username varchar (50), 
                password varchar (255),
                email varchar (255),
                role_id integer,
                organization_id integer REFERENCES Organizations (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS Roles (
                id serial primary key, 
                name varchar (50),
                write_local boolean,
                read_local boolean,
                read_all boolean,
                write_all boolean
        );

        CREATE TABLE IF NOT EXISTS Exercise_dbs (
                id serial primary key,
                name varchar (50),
                organization_id integer REFERENCES Organizations (id) ON DELETE CASCADE,
                url varchar (255),
                sign_key varchar (255),
                auth_key varchar (255),
                UNIQUE (name)
        );

        CREATE TABLE IF NOT EXISTS Haaukins_agents (
                id serial primary key, 
                url varchar (255),
                sign_key varchar (255),
                auth_key varchar (255)
        );

        CREATE TABLE IF NOT EXISTS Frontends (
                id serial primary key, 
                name varchar (50),
                image varchar (50),
                memoryMB integer
        );
        -- Setting up an administrative account with password admin
        INSERT INTO Organizations (name) VALUES ('Administrators');
        INSERT INTO Roles (name, write_local, read_local, read_all, write_all) VALUES ('SuperAdmin', true, true, true, true);
        INSERT INTO Admin_users (username, password, email, role_id, organization_id) VALUES ('Administrator', '\$2a\$10\$s8RIrctKwSA/jib7jSaGE.Z4TdukcRP/Irkxse5dotyYT0uHb3b.2', 'cyber@es.aau.dk', (SELECT id FROM Roles WHERE name = 'SuperAdmin'), (SELECT id FROM Organizations WHERE name = 'Administrators'));
        
EOSQL