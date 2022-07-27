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
                tag varchar (50) NOT NULL, 
                name varchar (150) NOT NULL, 
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
                tag varchar(50) NOT NULL,
                event_id integer NOT NULL,
                email varchar (50) NOT NULL,
                name varchar (50) NOT NULL, 
                password varchar (250) NOT NULL,
                created_at timestamp NOT NULL,
                last_access timestamp NOT NULL,
                solved_challenges text NOT NULL
        );

        CREATE TABLE IF NOT EXISTS Organizations (
                id serial primary key,
                name varchar (50) NOT NULL
        );
        CREATE UNIQUE INDEX orgname_lower_index ON Organizations (LOWER(name));

        CREATE TABLE IF NOT EXISTS Profiles (
                id serial primary key, 
                name varchar (50) NOT NULL, 
                secret boolean NOT NULL, 
                organization_id integer NOT NULL REFERENCES Organizations (id) ON DELETE CASCADE,
                challenges text NOT NULL
        );        
        CREATE UNIQUE INDEX profilename_lower_index ON Profiles (LOWER(name));

        CREATE TABLE IF NOT EXISTS Admin_users (
                id serial primary key, 
                username varchar (50) NOT NULL, 
                password varchar (255) NOT NULL,
                email varchar (255) NOT NULL,
                role_id integer NOT NULL,
                organization_id integer NOT NULL REFERENCES Organizations (id) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX username_lower_index ON Admin_users (LOWER(username));

        CREATE TABLE IF NOT EXISTS Roles (
                id serial primary key, 
                name varchar (50) NOT NULL,
                write_all boolean NOT NULL,
                read_all boolean NOT NULL,
                write_local boolean NOT NULL,
                read_local boolean NOT NULL
        );
        CREATE UNIQUE INDEX rolename_lower_index ON Roles (LOWER(name));

        CREATE TABLE IF NOT EXISTS Exercise_dbs (
                id serial primary key,
                name varchar (50) NOT NULL,
                organization_id integer NOT NULL REFERENCES Organizations (id) ON DELETE CASCADE, 
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
                name varchar (50) NOT NULL,
                image varchar (50) NOT NULL,
                memoryMB integer
        );
        CREATE UNIQUE INDEX frontendname_lower_index ON Frontends (LOWER(name));


        -- Setting up an administrative account with password admin
        INSERT INTO Organizations (name) VALUES ('Administrators');
        INSERT INTO Organizations (name) VALUES ('AAU');
        INSERT INTO Organizations (name) VALUES ('DTU');
        INSERT INTO Roles (name, write_all, read_all, write_local, read_local) VALUES ('SuperAdmin', true, true, true, true);
        INSERT INTO Roles (name, write_all, read_all, write_local, read_local) VALUES ('SuperAdminNoWrite', false, true, false, true);
        INSERT INTO Roles (name, write_all, read_all, write_local, read_local) VALUES ('Administrator', false, false, true, true);
        INSERT INTO Roles (name, write_all, read_all, write_local, read_local) VALUES ('AdministratorNoWrite', false, false, false, true);
        INSERT INTO Admin_users (username, password, email, role_id, organization_id) VALUES ('Administrator', '\$2a\$10\$s8RIrctKwSA/jib7jSaGE.Z4TdukcRP/Irkxse5dotyYT0uHb3b.2', 'cyber@es.aau.dk', (SELECT id FROM Roles WHERE name = 'SuperAdmin'), (SELECT id FROM Organizations WHERE name = 'Administrators'));
        
EOSQL