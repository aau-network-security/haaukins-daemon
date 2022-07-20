#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        CREATE USER $HAAUKINSDB_USER;
        ALTER USER $HAAUKINSDB_USER WITH PASSWORD '$HAAUKINSDB_PASSWORD';
        CREATE DATABASE $HAAUKINSDB_NAME;
        GRANT ALL PRIVILEGES ON DATABASE $HAAUKINSDB_NAME TO $HAAUKINSDB_USER;
EOSQL

PGPASSWORD=$HAAUKINSDB_PASSWORD psql -v ON_ERROR_STOP=1 --username "$HAAUKINSDB_USER" --dbname "$HAAUKINSDB_NAME" <<-EOSQL
        CREATE TABLE IF NOT EXISTS Event( 
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
            disabledExercises text);

        CREATE TABLE IF NOT EXISTS Team(
		    id serial primary key,
            tag varchat(50),
		    event_id integer,
		    email varchar (50),
		    name varchar (50), 
		    password varchar (250),
		    created_at timestamp,
		    last_access timestamp,
		    solved_challenges text);

        CREATE TABLE IF NOT EXISTS Profiles(
		    id serial primary key, 
		    name varchar (50), 
		    secret boolean, 
		    challenges text);
EOSQL