INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT IFNULL(MAX(id) + 1, 1), 'Garcilaso', 'de la Vega', 'CZ9250512252717368964232', 100, null, CURRENT_TIMESTAMP FROM account;
INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT MAX(id) + 1, 'Miguel', 'de Cervantes', 'SK0389852379529966291984', 100, null, CURRENT_TIMESTAMP FROM account;
INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT MAX(id) + 1, 'Luis', 'de Góngora', 'ES8521006742088984966816', 100, null, CURRENT_TIMESTAMP FROM account;
INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT MAX(id) + 1, 'Lope', 'de Vega', 'FR9317569000409377431694J37', 100, null, CURRENT_TIMESTAMP FROM account;
INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT MAX(id) + 1, 'Francisco', 'Quevedo', 'ES8521006742088984966817', 100, null, CURRENT_TIMESTAMP FROM account;
INSERT INTO account (id, name, lastName, accountNumber, amount, updatedAt, createdAt) SELECT MAX(id) + 1, 'Eduardo', 'Mendoza', 'ES8521006742088984966899', 100, null, CURRENT_TIMESTAMP FROM account;
UPDATE account_SEQ SET next_val=(SELECT MAX(id) + 1 FROM account);

INSERT INTO client (id, name, lastName, account_number) VALUES (100, 'Francisco', 'Quevedo', 'ES8521006742088984966817');
INSERT INTO client (id, name, lastName, account_number) VALUES (101, 'Eduardo', 'Mendoza', 'ES8521006742088984966899');

CREATE TABLE IF NOT EXISTS recovery_log (id INT);