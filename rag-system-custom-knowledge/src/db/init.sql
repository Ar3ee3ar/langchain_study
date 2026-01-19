CREATE TABLE users (
    id integer NOT NULL PRIMARY KEY,
    username character varying(50) NOT NULL,
    password character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_login timestamp without time zone,
    is_superuser boolean DEFAULT false NOT NULL,
    first_name character varying(150) DEFAULT ''::character varying NOT NULL,
    last_name character varying(150) DEFAULT ''::character varying NOT NULL,
    email character varying(254) DEFAULT ''::character varying NOT NULL,
    is_staff boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    date_joined timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE api_usage (
    id integer NOT NULL PRIMARY KEY, 
    user_id INTEGER REFERENCES users(id), 
    active boolean NOT NULL, 
    key_name VARCHAR(50) NOT NULL, 
    api_key UUID NOT NULL, 
    monthly_credits INTEGER DEFAULT 0, 
    curr_credits INTEGER NOT NULL DEFAULT 0, 
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT now() NOT NULL);

-- using trigger
-- -- to update updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_set_updated_at
BEFORE UPDATE ON api_usage
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- add unique
ALTER TABLE ONLY users
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE ONLY api_usage 
    ADD CONSTRAINT api_usage_api_key_key UNIQUE(api_key);

-- add data
COPY users (id, username, password, created_at, last_login, is_superuser, first_name, last_name, email, is_staff, is_active, date_joined) FROM stdin;
1	arzeezar	test1234	2025-08-25 20:45:50.997225	2025-08-29 08:03:05.76055	f				f	t	2025-08-28 22:00:32.126631
\.

