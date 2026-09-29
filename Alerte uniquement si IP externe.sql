/* =====================================================
    ALERTE EMAIL UNIQUEMENT SI IP EXTERNE
===================================================== */

-------------------------------------------------------
-- 1 Fonction : détecter IP interne
-------------------------------------------------------

CREATE OR REPLACE FUNCTION is_internal_ip(ip TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    IF ip IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Localhost
    IF ip LIKE '127.%' THEN
        RETURN TRUE;
    END IF;

    -- 192.168.x.x
    IF ip LIKE '192.168.%' THEN
        RETURN TRUE;
    END IF;

    -- 10.x.x.x
    IF ip LIKE '10.%' THEN
        RETURN TRUE;
    END IF;

    -- 172.16.x.x → 172.31.x.x
    IF ip ~ '^172\.(1[6-9]|2[0-9]|3[0-1])\.' THEN
        RETURN TRUE;
    END IF;

    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 2 Fonction d’envoi email
-------------------------------------------------------

CREATE OR REPLACE FUNCTION send_security_alert(
    blocked_user TEXT,
    action_count INTEGER,
    client_ip TEXT
)
RETURNS VOID AS $$
DECLARE
    subject TEXT;
    body TEXT;
    cmd TEXT;
BEGIN

    subject := 'ALERTE SECURITE - IP EXTERNE DETECTEE';

    body := 'ALERTE SECURITE

Utilisateur bloque : ' || blocked_user || '
Nombre actions suspectes : ' || action_count || '
IP externe detectee : ' || client_ip || '
Date : ' || NOW() || '

Verification immediate requise.
';

    cmd := format(
        $$echo "Subject: %s
To: admin@ecole.com
From: serveur@ecole.com

%s" | sendmail -t$$,
        subject,
        body
    );

    EXECUTE 'COPY (SELECT 1) TO PROGRAM ' || quote_literal(cmd);

END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-------------------------------------------------------
-- 3 Mise à jour de la fonction de blocage
-------------------------------------------------------

CREATE OR REPLACE FUNCTION detect_and_block_user()
RETURNS TRIGGER AS $$
DECLARE
    max_actions INTEGER := 5;
    time_window INTERVAL := '2 minutes';
    action_count INTEGER;
    ip TEXT;
BEGIN

    ip := NEW.client_addr;

    SELECT COUNT(*) INTO action_count
    FROM audit_log
    WHERE username = NEW.username
    AND date_action >= NOW() - time_window;

    IF action_count >= max_actions THEN

        EXECUTE format('ALTER ROLE %I NOLOGIN;', NEW.username);

        INSERT INTO security_monitor(username, tentative_count, blocked)
        VALUES (NEW.username, action_count, TRUE)
        ON CONFLICT (username)
        DO UPDATE SET 
            tentative_count = action_count,
            blocked = TRUE,
            last_activity = NOW();

        --  Alerte seulement si IP externe
        IF NOT is_internal_ip(ip) THEN
            PERFORM send_security_alert(NEW.username, action_count, ip);
        END IF;

    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 4 Vérification
-------------------------------------------------------

-- SELECT is_internal_ip('192.168.1.10');  -- TRUE
-- SELECT is_internal_ip('8.8.8.8');       -- FALSE
