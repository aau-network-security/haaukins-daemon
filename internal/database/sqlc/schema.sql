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


-- Admin related tables
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

