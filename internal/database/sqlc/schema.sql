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


-- Admin related tables
CREATE TABLE IF NOT EXISTS Organizations (
        id serial primary key,
        name varchar (50) NOT NULL
);

CREATE TABLE IF NOT EXISTS Profiles (
        id serial primary key, 
        name varchar (50) NOT NULL, 
        secret boolean NOT NULL, 
        organization_id integer NOT NULL REFERENCES Organizations (id) ON DELETE CASCADE,
        challenges text NOT NULL
);        

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
        write_local boolean NOT NULL,
        read_local boolean NOT NULL,
        read_all boolean NOT NULL,
        write_all boolean NOT NULL
);

CREATE TABLE IF NOT EXISTS Exercise_dbs (
        id serial primary key,
        name varchar (50) NOT NULL,
        organization_id integer NOT NULL REFERENCES Organizations (id) ON DELETE CASCADE, 
        url varchar (255) NOT NULL,
        sign_key varchar (255) NOT NULL,
        auth_key varchar (255) NOT NULL,
        UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS Haaukins_agents (
        id serial primary key, 
        url varchar (255) NOT NULL,
        sign_key varchar (255) NOT NULL,
        auth_key varchar (255) NOT NULL
);

CREATE TABLE IF NOT EXISTS Frontends (
    id serial primary key, 
    name varchar (50) NOT NULL,
    image varchar (50) NOT NULL,
    memoryMB integer
);

