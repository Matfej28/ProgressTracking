CREATE TABLE `users` (
	`Username` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_0900_ai_ci',
	`Email` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_0900_ai_ci',
	`Salt` BINARY(16) NOT NULL,
	`HashedPassword` BINARY(128) NOT NULL,
	UNIQUE INDEX `Username` (`Username`) USING BTREE,
	UNIQUE INDEX `Email` (`Email`) USING BTREE
)
COLLATE='utf8mb4_0900_ai_ci'
ENGINE=InnoDB
;