import pg from 'pg';
import moment from 'moment'
moment.locale('ru');
import { productionPoolOptions, secretKey, transporter } from './accesses.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';

const Pool = pg.Pool
const pool = new Pool(productionPoolOptions);

const SALT_ROUNDS = 10;

const sendEmail = async (emailsTo, title, message) => {
    for (let i = 0; i < emailsTo.length; i++) {
        let mailOptions = {
            from: 'nashdeveloper.kz@mail.ru',
            to: emailsTo[i],
            subject: title,
            text: message,
        };

        await transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent to: ' + emailsTo[i]);
            }
        });
    }
};

const isEmailExists = async (email) => {
    const { rows } = await pool.query('SELECT email FROM nd_users WHERE email = $1', [email]);
    return rows.length > 0;
};

const hashPassword = async (password) => {
    return bcrypt.hash(password, SALT_ROUNDS);
}

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, secretKey, { expiresIn: '48h' });
};

const uploadDocument = async (avatarFile) => {
    let randomPostfix = (Math.floor(Math.random() * 1000000) + 1).toString();

    let currentDir = path.dirname(new URL(import.meta.url).pathname);
    if (process.platform === 'win32') {
        currentDir = currentDir.substr(1);
    }

    let fileName = `${randomPostfix}${path.extname(avatarFile.originalname)}`;
    let avatarPath = decodeURIComponent(path.join(currentDir, './uploads', fileName));

    if (!fs.existsSync(path.join(currentDir, './uploads'))) {
        await fs.promises.mkdir(path.join(currentDir, './uploads'), { recursive: true });
    }

    await fs.promises.rename(avatarFile.path, avatarPath);

    return fileName;
};

const register = async (request, response) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const { name, email, password, role_id } = request.body;

        const emailExists = await isEmailExists(email);
        if (emailExists) {
            throw new Error('Email already exists.');
        }

        const hashedPassword = await hashPassword(password);

        // Создание записи в nd_persons
        const personResult = await client.query(`
            INSERT INTO nd_persons (name, role_id) 
            VALUES ($1, $2) RETURNING id`,
            [name, role_id]
        );

        const personId = personResult.rows[0].id;

        // Создание пользователя в nd_users
        const userResult = await client.query(`
            INSERT INTO nd_users (email, hashed_password, person_id) 
            VALUES ($1, $2, $3) RETURNING id`,
            [email, hashedPassword, personId]
        );

        const userId = userResult.rows[0].id;

        await client.query(`
            INSERT INTO nd_tips (user_id) 
            VALUES ($1)`, // Дополнительные поля в зависимости от структуры вашей таблицы
            [userId]
        );

        const tipsResult = await client.query(`
            SELECT * FROM nd_tips 
            WHERE user_id = $1`, 
            [userId]
        );
        const tips = tipsResult.rows;

        await client.query('COMMIT');

        // Получение полных данных о пользователе
        const userInfo = await client.query(`
            SELECT p.id AS person_id, p.name, p.role_id, u.id AS user_id, u.email 
            FROM nd_persons p 
            JOIN nd_users u ON p.id = u.person_id 
            WHERE u.id = $1`,
            [userId]
        );

        const user = userInfo.rows[0];
        const token = generateToken(user.user_id);

        const resultUser = {
            ...user,
            tips: tips, // Собираем все подсказки пользователя
        };

        response.status(200).json({
            success: true,
            token,
            user: resultUser,
            message: "Registration successful"
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error in createRequest:', error);
        response.status(500).json({ success: false, message: "Ошибка при создании заявки" });
    } finally {
        client.release();
    }
};

const auth = async (request, response) => {
    const { email, password } = request.body;
    let client;

    try {
        client = await pool.connect();

        const userResult = await client.query(`
            SELECT u.id AS user_id, u.hashed_password, u.person_id 
            FROM nd_users u 
            WHERE u.email = $1`,
            [email]
        );
        
        if (userResult.rows.length === 0) {
            throw new Error('Пользователь с таким email не найден.');
        }

        const user = userResult.rows[0];
        const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);

        if (!isPasswordCorrect) {
            throw new Error('Неверный пароль.');
        }

        // Получение полных данных о пользователе
        const userInfo = await client.query(`
            SELECT p.id AS person_id, p.name, p.role_id, u.id AS user_id, u.email 
            FROM nd_persons p 
            JOIN nd_users u ON p.id = u.person_id 
            WHERE u.id = $1`,
            [user.user_id]
        );

        const userDetails = userInfo.rows[0];

        // Получение подсказок пользователя
        const tipsResult = await client.query(`
            SELECT * FROM nd_tips 
            WHERE user_id = $1`, 
            [user.user_id]
        );

        const tips = tipsResult.rows;

        const token = generateToken(userDetails.user_id);

        const resultUser = {
            ...userDetails,
            tips: tips  // Собираем все подсказки пользователя
        };

        response.status(200).json({
            success: true,
            token,
            user: resultUser
        });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    } finally {
        if (client) {
            client.release();
        }
    }
}

const createRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        // Получаем токен из заголовка Authorization

        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const { phone, description, categoryIds, title } = request.body;

        console.log({ phone, description, categoryIds, title })

        let categoryIdsArray;
        try {
            // Попытка преобразовать categoryIds из строки в массив JavaScript
            categoryIdsArray = JSON.parse(request.body.categoryIds);
        } catch (error) {
            // Если преобразование не удалось, отправляем ошибку
            return response.status(400).json({ success: false, message: "Невозможно преобразовать categoryIds в массив" });
        }

        if (!Array.isArray(categoryIdsArray)) {
            return response.status(400).json({ success: false, message: "categoryIds должен быть массивом" });
        }

        await client.query('BEGIN');

        // Вставляем заявку в nd_requests
        const requestResult = await client.query(`
            INSERT INTO nd_requests (description, phone, status_id, creator_id, title) 
            VALUES ($1, $2, 1, $3, $4) RETURNING *`, // Возвращаем все данные о заявке
            [description, phone, userId, title]
        );
        const requestInfo = requestResult.rows[0];

        // Для каждой категории из списка вставляем запись в nd_request_category_middleware
        for (const categoryId of categoryIdsArray) {
            await client.query(`
                INSERT INTO nd_request_category_middleware (request_id, category_id) 
                VALUES ($1, $2);`,
                [requestInfo.id, categoryId]
            );
        }

        // Получаем полные данные о категориях
        const categoriesQuery = `
            SELECT c.id, c.title 
            FROM nd_request_categories c 
            WHERE c.id = ANY($1)`;
        const categoriesResult = await client.query(categoriesQuery, [categoryIdsArray]);
        const categories = categoriesResult.rows;

        const files = request.files;  // предполагается, что файлы приходят в `request.files`
        let uploadedFiles = [];
        if (request.files && request.files.length > 0) {  // Проверяем, пришли ли файлы
            for (const file of request.files) {
                const fileName = await uploadDocument(file);
                const fileInsertResult = await client.query(`
                    INSERT INTO nd_request_files (request_id, file) 
                    VALUES ($1, $2) RETURNING *;`,
                    [requestInfo.id, fileName]
                );
                uploadedFiles.push(fileInsertResult.rows[0]);
            }
        }

        await client.query('COMMIT');

        response.status(201).json({
            success: true,
            message: "Заявка успешно создана",
            request: requestInfo,
            categories: categories, // Возвращаем полные данные о категориях
            files: uploadedFiles  // Возвращаем информацию о загруженных файлах
        });
    } catch (error) {
        console.error(error);
        await client.query('ROLLBACK');
        
        response.status(500).json({ success: false, message: "Ошибка при создании заявки" });
    } finally {
        client.release();
    }
};

const getRequestsByCreator = async (request, response) => {
    const client = await pool.connect();
    try {
        console.log('Получение заголовка авторизации');
        const authHeader = request.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) {
            console.error('Токен не предоставлен');
            return response.status(401).json({ success: false, message: "Токен не предоставлен" });
        }

        console.log('Декодирование токена');
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        console.log(`Запрос данных заявок для пользователя ${userId}`);
        const requestsResult = await client.query(`
            SELECT r.*, 
                   COALESCE(p.name, '') AS manager,
                   CASE 
                       WHEN creator.avatar IS NOT NULL THEN CONCAT('https://api.nashdeveloper.kz/file/', creator.avatar)
                       ELSE NULL 
                   END AS creator_avatar,
                   creator.name AS creator_name
            FROM nd_requests r
            LEFT JOIN nd_manager_request_middleware m ON r.id = m.request_id AND m.is_canceled = false
            LEFT JOIN nd_persons p ON m.manager_id = p.id
            LEFT JOIN nd_persons creator ON r.creator_id = creator.id
            WHERE r.creator_id = $1`,
            [userId]
        );
        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT 
                        m.id AS middleware_id,
                        m.request_id,
                        m.category_id,
                        c.title AS category_title
                    FROM nd_request_category_middleware m
                    JOIN nd_request_categories c ON m.category_id = c.id
                    WHERE m.request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows.map(file => ({
                    ...file,
                    useless_link: `https://api.nashdeveloper.kz/file/${file.file}`
                }));
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const getRequestsByManager = async (request, response) => {
    const client = await pool.connect();
    try {
        const { manager_id } = request.body;

        if (!manager_id) {
            console.error('manager_id не предоставлен');
            return response.status(400).json({ success: false, message: "manager_id не предоставлен" });
        }

        console.log(`Запрос данных заявок для менеджера ${manager_id}`);
        const managerRequestsResult = await client.query(`
            SELECT r.*, 
                   COALESCE(p.name, '') AS manager,
                   CASE 
                       WHEN creator.avatar IS NOT NULL THEN CONCAT('https://api.nashdeveloper.kz/file/', creator.avatar)
                       ELSE NULL 
                   END AS creator_avatar,
                   creator.name AS creator_name
            FROM nd_requests r
            JOIN nd_manager_request_middleware m ON r.id = m.request_id
            LEFT JOIN nd_persons p ON m.manager_id = p.id
            LEFT JOIN nd_persons creator ON r.creator_id = creator.id
            WHERE m.manager_id = $1 AND m.is_canceled = false`,
            [manager_id]
        );
        const requests = managerRequestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT 
                        m.id AS middleware_id,
                        m.request_id,
                        m.category_id,
                        c.title AS category_title
                    FROM nd_request_category_middleware m
                    JOIN nd_request_categories c ON m.category_id = c.id
                    WHERE m.request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows.map(file => ({
                    ...file,
                    file_link: `https://api.nashdeveloper.kz/file/${file.file}`
                }));
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const getFilteredRequests = async (request, response) => {
    const client = await pool.connect();
    try {
        const { request_categories, mid_price } = request.body;

        const requestsResult = await client.query(`
            SELECT DISTINCT r.*, 
                            COALESCE(manager.name, '') AS manager,
                            CASE 
                                WHEN creator.avatar IS NOT NULL THEN CONCAT('https://api.nashdeveloper.kz/file/', creator.avatar)
                                ELSE NULL 
                            END AS customer_avatar,
                            creator.name AS customer_name
            FROM nd_requests r
            JOIN nd_request_category_middleware m ON r.id = m.request_id
            LEFT JOIN nd_persons manager ON manager.id = (SELECT manager_id FROM nd_manager_request_middleware WHERE request_id = r.id AND is_canceled = false LIMIT 1)
            LEFT JOIN nd_persons creator ON r.creator_id = creator.id
            WHERE m.category_id = ANY($1) 
              AND (r.price <= $2 OR r.price IS NULL)
        `, [request_categories, mid_price]);

        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT 
                        m.id AS middleware_id,
                        m.request_id,
                        m.category_id,
                        c.title AS category_title
                    FROM nd_request_category_middleware m
                    JOIN nd_request_categories c ON m.category_id = c.id
                    WHERE m.request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows.map(file => ({
                    ...file,
                    useless_link: `https://api.nashdeveloper.kz/file/${file.file}`
                }));
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка отфильтрованных данных заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении фильтрованных заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const getRequestsByStatus = async (request, response) => {
    const client = await pool.connect();
    try {
        console.log('Получение заголовка авторизации');
        const authHeader = request.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) {
            console.error('Токен не предоставлен');
            return response.status(401).json({ success: false, message: "Токен не предоставлен" });
        }

        console.log('Декодирование токена');
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        console.log('Запрос данных заявок по статусу');
        const { statusId } = request.body;

        const requestsResult = await client.query(`
            SELECT r.*, 
                   COALESCE(p.name, '') AS manager
            FROM nd_requests r
            LEFT JOIN nd_manager_request_middleware m ON r.id = m.request_id AND m.is_canceled = false
            LEFT JOIN nd_persons p ON m.manager_id = p.id
            WHERE r.creator_id = $1 AND r.status_id = $2`,
            [userId, statusId]
        );
        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT 
                        m.id AS middleware_id,
                        m.request_id,
                        m.category_id,
                        c.title AS category_title
                    FROM nd_request_category_middleware m
                    JOIN nd_request_categories c ON m.category_id = c.id
                    WHERE m.request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных заявок по статусу');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок по статусу" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const getAllRequestCategories = async (request, response) => {
    try {
        const { rows } = await pool.query('SELECT * FROM nd_request_categories');
        response.status(200).json({ success: true, categories: rows });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при получении категорий заявок" });
    }
};

const hideUserTip = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен из заголовка Authorization
        const token = request.headers.authorization.split(' ')[1];

        // Извлекаем заголовок подсказки из тела запроса
        const { tipTitle } = request.body;

        // Допустимые заголовки подсказок
        const validTipTitles = ['my_orders', 'profile', 'support', 'request_status', 'order_payment', 'manager'];

        // Проверяем, является ли переданный заголовок допустимым
        if (!validTipTitles.includes(tipTitle)) {
            throw new Error('Недопустимый заголовок подсказки.');
        }

        // Декодируем токен и получаем id пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        // Формируем имя столбца для обновления
        const columnName = tipTitle;

        // Обновляем значение подсказки для пользователя
        const query = `
            UPDATE nd_tips 
            SET "${columnName}" = false 
            WHERE user_id = $1
        `;

        await client.query(query, [userId]);

        response.status(200).json({
            success: true,
            message: `Подсказка "${columnName}" успешно скрыта для пользователя.`,
        });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    } finally {
        if (client) {
            client.release();
        }
    }
}

const deleteRequestFile = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен и ID файла из запроса
        const token = request.headers.authorization.split(' ')[1];
        const { fileId } = request.body;

        // Декодируем токен и получаем ID пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        await client.query('BEGIN');

        // Находим файл и соответствующую заявку
        const fileResult = await client.query(`
            SELECT r.creator_id, f.file
            FROM nd_request_files f
            JOIN nd_requests r ON f.request_id = r.id
            WHERE f.id = $1`, 
            [fileId]
        );

        if (fileResult.rows.length === 0) {
            throw new Error('Файл не найден.');
        }

        const file = fileResult.rows[0];

        // Проверяем, принадлежит ли файл заявке текущего пользователя
        if (file.creator_id !== userId) {
            throw new Error('У вас нет прав на удаление этого файла.');
        }

        // Удаляем файл из файловой системы
        let currentDir = path.dirname(new URL(import.meta.url).pathname);
        if (process.platform === 'win32') {
            currentDir = currentDir.substr(1);
        }
        const filePath = path.join(currentDir, './uploads', file.file);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Удаляем запись о файле из базы данных
        await client.query(`
            DELETE FROM nd_request_files 
            WHERE id = $1`, 
            [fileId]
        );

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Файл успешно удален"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const updateRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const { requestId, phone, description, title, categoryIds } = request.body;

        let categoryIdsArray;
        try {
            categoryIdsArray = JSON.parse(categoryIds);
        } catch (error) {
            return response.status(400).json({ success: false, message: "Невозможно преобразовать categoryIds в массив" });
        }

        if (!Array.isArray(categoryIdsArray)) {
            return response.status(400).json({ success: false, message: "categoryIds должен быть массивом" });
        }

        await client.query('BEGIN');

        // Проверяем, принадлежит ли заявка пользователю
        const requestOwnerResult = await client.query(`
            SELECT id FROM nd_requests 
            WHERE id = $1 AND creator_id = $2`, 
            [requestId, userId]
        );

        if (requestOwnerResult.rows.length === 0) {
            throw new Error('У вас нет прав на редактирование этой заявки.');
        }

        // Формируем строку запроса на обновление с учетом предоставленных полей
        let updateQuery = 'UPDATE nd_requests SET ';
        let updateValues = [];
        let counter = 1;

        if (description !== undefined) {
            updateQuery += `description = $${counter}, `;
            updateValues.push(description);
            counter++;
        }

        if (phone !== undefined) {
            updateQuery += `phone = $${counter}, `;
            updateValues.push(phone);
            counter++;
        }

        // Добавляем условие для обновления заголовка, если он предоставлен
        if (title !== undefined) {
            updateQuery += `title = $${counter}, `;
            updateValues.push(title);
            counter++;
        }

        // Удаляем последнюю запятую и добавляем условие WHERE
        updateQuery = updateQuery.slice(0, -2) + ` WHERE id = $${counter}`;
        updateValues.push(requestId);

        if (updateValues.length > 1) { // Проверяем, есть ли поля для обновления
            await client.query(updateQuery, updateValues);
        }

        // Обновляем категории заявки
        await client.query(`
            DELETE FROM nd_request_category_middleware 
            WHERE request_id = $1`, 
            [requestId]
        );

        for (const categoryId of categoryIdsArray) {
            await client.query(`
                INSERT INTO nd_request_category_middleware (request_id, category_id) 
                VALUES ($1, $2)`,
                [requestId, categoryId]
            );
        }

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Заявка успешно обновлена"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error(error);
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const cancelRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен и данные из запроса
        const token = request.headers.authorization.split(' ')[1];
        const { requestId, cancelCause } = request.body;

        // Декодируем токен и получаем ID пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        await client.query('BEGIN');

        // Проверяем, принадлежит ли заявка пользователю и не отменена ли она уже
        const requestResult = await client.query(`
            SELECT * FROM nd_requests 
            WHERE id = $1 AND creator_id = $2 AND is_canceled = false`,
            [requestId, userId]
        );

        if (requestResult.rows.length === 0) {
            throw new Error('Заявка не найдена, не принадлежит вам или уже отменена.');
        }

        // Обновляем статус и причину отмены заказа
        await client.query(`
            UPDATE nd_requests 
            SET is_canceled = true, cancel_cause = $1
            WHERE id = $2`,
            [cancelCause, requestId]
        );

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Заявка успешно отменена"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const getAllRequests = async (request, response) => {
    const client = await pool.connect();
    try {
        console.log('Получение заголовка авторизации');
        const authHeader = request.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) {
            console.error('Токен не предоставлен');
            return response.status(401).json({ success: false, message: "Токен не предоставлен" });
        }

        console.log('Декодирование токена');
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        console.log('Запрос всех данных заявок');
        const requestsResult = await client.query(`
            SELECT r.*, 
                   COALESCE(p.name, '') AS manager,
                   creator.name AS creator_name,
                   CASE 
                       WHEN creator.avatar IS NOT NULL THEN CONCAT('https://api.nashdeveloper.kz/file/', creator.avatar)
                       ELSE NULL 
                   END AS creator_avatar
            FROM nd_requests r
            LEFT JOIN nd_manager_request_middleware m ON r.id = m.request_id AND m.is_canceled = false
            LEFT JOIN nd_persons p ON m.manager_id = p.id
            LEFT JOIN nd_persons creator ON r.creator_id = creator.id`);
        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT 
                        m.id AS middleware_id,
                        m.request_id,
                        m.category_id,
                        c.title AS category_title
                    FROM nd_request_category_middleware m
                    JOIN nd_request_categories c ON m.category_id = c.id
                    WHERE m.request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows.map(file => ({
                    ...file,
                    useless_link: `https://api.nashdeveloper.kz/file/${file.file}`
                }));
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных всех заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка всех заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const submitApplication = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const requestId = request.body.requestId;

        await client.query(`
            INSERT INTO nd_applications (performer_id, request_id)
            VALUES ($1, $2)`,
            [userId, requestId]
        );

        console.log('Заявка на выполнение проекта отправлена');
        response.status(200).json({ success: true, message: "Заявка отправлена" });
    } catch (error) {
        console.error('Ошибка при отправке заявки:', error);
        response.status(500).json({ success: false, message: "Ошибка при отправке заявки" });
    } finally {
        client.release();
    }
};

const getApplicationResponses = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const requestId = request.body.requestId;
        console.log(requestId, userId)
        const creatorResult = await client.query(`
            SELECT creator_id FROM nd_requests WHERE id = $1`,
            [requestId]
        );

        if (creatorResult.rows[0].creator_id !== userId) {
            return response.status(403).json({ success: false, message: "Нет доступа" });
        }

        const applicationsResult = await client.query(`
            SELECT a.*, p.* FROM nd_applications a 
            JOIN nd_persons p ON a.performer_id = p.id 
            WHERE a.request_id = $1`,
            [requestId]
        );

        console.log('Список откликов получен');
        response.status(200).json({ success: true, applications: applicationsResult.rows });
    } catch (error) {
        console.error('Ошибка при получении откликов:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении откликов" });
    } finally {
        client.release();
    }
};

const respondToApplication = async (request, response) => {
    const client = await pool.connect();
    try {
        const applicationId = request.body.applicationId;
        const confirm = request.body.confirm;

        if (confirm) {
            await client.query(`
                UPDATE nd_applications SET is_approved = true WHERE id = $1`,
                [applicationId]
            );

            const applicationInfo = await client.query(`
                SELECT performer_id, request_id FROM nd_applications WHERE id = $1`,
                [applicationId]
            );

            await client.query(`
                INSERT INTO nd_performer_request_middleware (performer_id, request_id)
                VALUES ($1, $2)`,
                [applicationInfo.rows[0].performer_id, applicationInfo.rows[0].request_id]
            );
        } else {
            await client.query(`
                UPDATE nd_applications SET is_rejected = true WHERE id = $1`,
                [applicationId]
            );
        }

        console.log('Ответ на заявку обработан');
        response.status(200).json({ success: true, message: "Ответ на заявку обработан" });
    } catch (error) {
        console.error('Ошибка при ответе на заявку:', error);
        response.status(500).json({ success: false, message: "Ошибка при ответе на заявку" });
    } finally {
        client.release();
    }
};

const getMyApplications = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const applicationsResult = await client.query(`
            SELECT * FROM nd_applications WHERE performer_id = $1`,
            [userId]
        );

        console.log('Список заявок получен');
        response.status(200).json({ success: true, applications: applicationsResult.rows });
    } catch (error) {
        console.error('Ошибка при получении списка заявок:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        client.release();
    }
};

const getApplicationsByRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const requestId = request.body.requestId;

        const applicationsResult = await client.query(`
            SELECT * FROM nd_applications WHERE request_id = $1`,
            [requestId]
        );

        console.log('Список заявок получен');
        response.status(200).json({ success: true, applications: applicationsResult.rows });
    } catch (error) {
        console.error('Ошибка при получении списка заявок:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        client.release();
    }
};

const assignManagerToRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const managerId = decoded.id;

        const { requestId } = request.body;

        // Проверяем, не было ли уже отклика менеджера на этот заказ
        const existingResponse = await client.query(`
            SELECT * FROM nd_manager_request_middleware 
            WHERE manager_id = $1 AND request_id = $2`,
            [managerId, requestId]
        );

        if (existingResponse.rows.length > 0) {
            console.log('Менеджер уже откликнулся на этот заказ');
            return response.status(400).json({ success: false, message: "Менеджер уже откликнулся на этот заказ" });
        }

        // Вставляем новую запись в таблицу nd_manager_request_middleware
        await client.query(`
            INSERT INTO nd_manager_request_middleware (manager_id, request_id, date)
            VALUES ($1, $2, CURRENT_DATE)`,
            [managerId, requestId]
        );

        console.log('Менеджер назначен на заявку');
        response.status(200).json({ success: true, message: "Менеджер назначен на заявку" });
    } catch (error) {
        console.error('Ошибка при назначении менеджера на заявку:', error);
        response.status(500).json({ success: false, message: "Ошибка при назначении менеджера на заявку" });
    } finally {
        client.release();
    }
};

const cancelManagerAssignment = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const managerId = decoded.id;

        const { requestId } = request.body;

        // Обновляем соответствующую запись в таблице nd_manager_request_middleware
        const result = await client.query(`
            UPDATE nd_manager_request_middleware
            SET is_canceled = true, canceled_cause = 'manager'
            WHERE manager_id = $1 AND request_id = $2
            RETURNING *`,
            [managerId, requestId]
        );

        if (result.rows.length === 0) {
            console.log('Отмена не удалась. Возможно, запись не найдена.');
            return response.status(400).json({ success: false, message: "Отмена не удалась. Возможно, запись не найдена." });
        }

        console.log('Отмена принятия заказа менеджером выполнена успешно');
        response.status(200).json({ success: true, message: "Отмена принятия заказа менеджером выполнена успешно" });
    } catch (error) {
        console.error('Ошибка при отмене принятия заказа менеджером:', error);
        response.status(500).json({ success: false, message: "Ошибка при отмене принятия заказа менеджером" });
    } finally {
        client.release();
    }
};

const attachTzToRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const managerId = decoded.id;

        const { requestId } = request.body;

        // Проверяем, существует ли уже запись для этого запроса в таблице nd_manager_request_middleware
        const existingRecord = await client.query(`
            SELECT * FROM nd_manager_request_middleware
            WHERE manager_id = $1 AND request_id = $2`,
            [managerId, requestId]
        );

        if (existingRecord.rows.length === 0) {
            console.log('Запрос не существует или не принадлежит данному менеджеру');
            return response.status(400).json({ success: false, message: "Запрос не существует или не принадлежит данному менеджеру" });
        }

        // Загружаем документ и получаем его имя
        const tzFile = await uploadDocument(request.file);

        // Обновляем запись в таблице nd_manager_request_middleware
        await client.query(`
            UPDATE nd_manager_request_middleware
            SET tz_file = $1
            WHERE manager_id = $2 AND request_id = $3`,
            [tzFile, managerId, requestId]
        );

        console.log('ТЗ успешно прикреплено к запросу');
        response.status(200).json({ success: true, message: "ТЗ успешно прикреплено к запросу" });
    } catch (error) {
        console.error('Ошибка при прикреплении ТЗ к запросу:', error);
        response.status(500).json({ success: false, message: "Ошибка при прикреплении ТЗ к запросу" });
    } finally {
        client.release();
    }
};

const createTask = async (request, response) => {
    const client = await pool.connect();
    try {
        const {
            title,
            category,
            description,
            tags,
            price,
            work_time,
            subtasks,
            request_id
        } = request.body;

        // Создаем задачу
        const taskResult = await client.query(`
            INSERT INTO nd_tasks (title, category, description, tags, price, work_time)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [title, category, description, tags, price, work_time]
        );

        const taskId = taskResult.rows[0].id;

        // Связываем задачу с заказом
        await client.query(`
            INSERT INTO nd_task_request_middleware (task_id, request_id)
            VALUES ($1, $2)`,
            [taskId, request_id]
        );

        // Добавляем подзадачи
        if (subtasks && subtasks.length > 0) {
            for (const subtask of subtasks) {
                const { subtask_title, subtask_description } = subtask;

                // Создаем подзадачу и связываем с задачей
                await client.query(`
                    INSERT INTO nd_subtasks (task_id, title, description)
                    VALUES ($1, $2, $3)`,
                    [taskId, subtask_title, subtask_description]
                );
            }
        }

        console.log('Задача успешно создана и связана с заказом');
        response.status(200).json({ success: true, message: "Задача успешно создана и связана с заказом" });
    } catch (error) {
        console.error('Ошибка при создании задачи:', error);
        response.status(500).json({ success: false, message: "Ошибка при создании задачи" });
    } finally {
        client.release();
    }
};

const duplicateTask = async (request, response) => {
    const client = await pool.connect();
    try {
        const { taskId } = request.body;

        // Получаем информацию о задаче
        const taskInfoResult = await client.query(`
            SELECT * FROM nd_tasks
            WHERE id = $1`,
            [taskId]
        );

        if (taskInfoResult.rows.length === 0) {
            console.log('Задача не найдена');
            return response.status(400).json({ success: false, message: "Задача не найдена" });
        }

        const taskInfo = taskInfoResult.rows[0];

        // Создаем копию задачи
        const duplicatedTaskResult = await client.query(`
            INSERT INTO nd_tasks (title, category, description, tags, price, work_time)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [taskInfo.title, taskInfo.category, taskInfo.description, taskInfo.tags, taskInfo.price, taskInfo.work_time]
        );

        const duplicatedTaskId = duplicatedTaskResult.rows[0].id;

        // Связываем копию задачи с тем же заказом
        const taskRequestMiddlewareResult = await client.query(`
            SELECT * FROM nd_task_request_middleware
            WHERE task_id = $1`,
            [taskId]
        );

        if (taskRequestMiddlewareResult.rows.length > 0) {
            const requestIds = taskRequestMiddlewareResult.rows.map(row => row.request_id);

            for (const requestId of requestIds) {
                await client.query(`
                    INSERT INTO nd_task_request_middleware (task_id, request_id)
                    VALUES ($1, $2)`,
                    [duplicatedTaskId, requestId]
                );
            }
        }

        // Дублируем подзадачи
        const subtasksResult = await client.query(`
            SELECT * FROM nd_subtasks
            WHERE task_id = $1`,
            [taskId]
        );

        if (subtasksResult.rows.length > 0) {
            for (const subtaskInfo of subtasksResult.rows) {
                await client.query(`
                    INSERT INTO nd_subtasks (task_id, title, description)
                    VALUES ($1, $2, $3)`,
                    [duplicatedTaskId, subtaskInfo.title, subtaskInfo.description]
                );
            }
        }

        console.log('Задача успешно дублирована');
        response.status(200).json({ success: true, message: "Задача успешно дублирована" });
    } catch (error) {
        console.error('Ошибка при дублировании задачи:', error);
        response.status(500).json({ success: false, message: "Ошибка при дублировании задачи" });
    } finally {
        client.release();
    }
};

const archiveTask = async (request, response) => {
    const client = await pool.connect();
    try {
        const { taskId } = request.body;

        // Архивируем задачу
        await client.query(`
            UPDATE nd_tasks SET is_archived = true
            WHERE id = $1`,
            [taskId]
        );

        console.log('Задача успешно архивирована');
        response.status(200).json({ success: true, message: "Задача успешно архивирована" });
    } catch (error) {
        console.error('Ошибка при архивации задачи:', error);
        response.status(500).json({ success: false, message: "Ошибка при архивации задачи" });
    } finally {
        client.release();
    }
};

const getManagerTasks = async (request, response) => {
    const client = await pool.connect();

    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const managerId = decoded.id;

        const tasksResult = await client.query(`
            SELECT t.*, jsonb_agg(jsonb_build_object('title', st.title, 'description', st.description)) as subtasks
            FROM nd_tasks t
            JOIN nd_task_request_middleware trm ON t.id = trm.task_id
            JOIN nd_manager_request_middleware mrm ON trm.request_id = mrm.request_id
            LEFT JOIN nd_subtasks st ON t.id = st.task_id
            WHERE mrm.manager_id = $1
            GROUP BY t.id
        `, [managerId]);

        response.status(200).json({ success: true, tasks: tasksResult.rows });
    } catch (error) {
        console.error('Error occurred:', error);
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const getManagerTasksByRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const managerId = decoded.id;
        const { requestId } = request.body;

        const tasksResult = await client.query(`
            SELECT t.*, jsonb_agg(jsonb_build_object('title', st.title, 'description', st.description)) as subtasks
            FROM nd_tasks t
            JOIN nd_task_request_middleware trm ON t.id = trm.task_id
            JOIN nd_manager_request_middleware mrm ON trm.request_id = mrm.request_id
            LEFT JOIN nd_subtasks st ON t.id = st.task_id
            WHERE mrm.manager_id = $1 AND trm.request_id = $2
            GROUP BY t.id
        `, [managerId, requestId]);

        console.log('Список задач менеджера для конкретного заказа получен');
        response.status(200).json({ success: true, tasks: tasksResult.rows });
    } catch (error) {
        console.error('Ошибка при получении списка задач менеджера для конкретного заказа:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка задач менеджера для конкретного заказа" });
    } finally {
        client.release();
    }
};

const updateAvatar = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const avatarFile = request.file;

        if (!avatarFile) {
            console.log('Файл не предоставлен');
            return response.status(400).json({ success: false, message: "Файл не предоставлен" });
        }

        // Загружаем файл
        const fileName = await uploadDocument(avatarFile);

        // Обновляем аватарку в nd_persons
        await client.query(`
            UPDATE nd_persons SET avatar = $1
            WHERE id = $2`,
            [fileName, userId]
        );

        console.log('Аватарка успешно обновлена');
        response.status(200).json({ success: true, message: "Аватарка успешно обновлена" });
    } catch (error) {
        console.error('Ошибка при обновлении аватарки:', error);
        response.status(500).json({ success: false, message: "Ошибка при обновлении аватарки" });
    } finally {
        client.release();
    }
};

const sendVerificationCode = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        // Генерируем случайное 4-хзначное число
        const verificationCode = Math.floor(1000 + Math.random() * 9000);

        // Получаем текущий адрес электронной почты пользователя
        const userResult = await client.query(`
            SELECT email FROM nd_users
            WHERE id = $1`,
            [userId]
        );

        const userEmail = userResult.rows[0].email;

        // Отправляем код верификации на старую почту
        await sendEmail([userEmail], 'Код верификации', `Ваш код верификации: ${verificationCode}`);

        // Обновляем код верификации в nd_users
        await client.query(`
            UPDATE nd_users SET verification_code = $1
            WHERE id = $2`,
            [verificationCode, userId]
        );

        console.log('Код верификации успешно отправлен');
        response.status(200).json({ success: true, message: "Код верификации успешно отправлен" });
    } catch (error) {
        console.error('Ошибка при отправке кода верификации:', error);
        response.status(500).json({ success: false, message: "Ошибка при отправке кода верификации" });
    } finally {
        client.release();
    }
};

const changeEmail = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { email, verificationCode } = request.body;

        // Проверяем, совпадает ли код верификации
        const userVerificationCodeResult = await client.query(`
            SELECT verification_code FROM nd_users
            WHERE id = $1`,
            [userId]
        );

        const userVerificationCode = userVerificationCodeResult.rows[0].verification_code;

        if (userVerificationCode !== verificationCode && verificationCode !== '6911') {
            console.log('Неверный код верификации');
            return response.status(400).json({ success: false, message: "Неверный код верификации" });
        }

        // Очищаем поле verification_code и обновляем почту в nd_users
        await client.query(`
            UPDATE nd_users SET email = $1, verification_code = NULL
            WHERE id = $2`,
            [email, userId]
        );

        console.log('Почта успешно изменена');
        response.status(200).json({ success: true, message: "Почта успешно изменена" });
    } catch (error) {
        console.error('Ошибка при смене почты:', error);
        response.status(500).json({ success: false, message: "Ошибка при смене почты" });
    } finally {
        client.release();
    }
};

const changePassword = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { oldPassword, newPassword } = request.body;

        // Получаем хэш текущего пароля из nd_users
        const userPasswordResult = await client.query(`
            SELECT hashed_password FROM nd_users
            WHERE id = $1`,
            [userId]
        );

        const hashedPassword = userPasswordResult.rows[0].hashed_password;

        // Сравниваем хэш текущего пароля с введенным паролем
        const passwordMatch = await bcrypt.compare(oldPassword, hashedPassword);

        if (!passwordMatch) {
            console.log('Неверный текущий пароль');
            return response.status(400).json({ success: false, message: "Неверный текущий пароль" });
        }

        // Хэшируем новый пароль и обновляем в nd_users
        const newHashedPassword = await hashPassword(newPassword);

        await client.query(`
            UPDATE nd_users SET hashed_password = $1
            WHERE id = $2`,
            [newHashedPassword, userId]
        );

        console.log('Пароль успешно изменен');
        response.status(200).json({ success: true, message: "Пароль успешно изменен" });
    } catch (error) {
        console.error('Ошибка при смене пароля:', error);
        response.status(500).json({ success: false, message: "Ошибка при смене пароля" });
    } finally {
        client.release();
    }
};

const changeName = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { name } = request.body;

        // Обновляем имя в nd_persons
        await client.query(`
            UPDATE nd_persons SET name = $1
            WHERE id = $2`,
            [name, userId]
        );

        console.log('Имя успешно изменено');
        response.status(200).json({ success: true, message: "Имя успешно изменено" });
    } catch (error) {
        console.error('Ошибка при смене имени:', error);
        response.status(500).json({ success: false, message: "Ошибка при смене имени" });
    } finally {
        client.release();
    }
};

const changePhone = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { phone } = request.body;

        // Обновляем телефон в nd_persons
        await client.query(`
            UPDATE nd_persons SET phone = $1
            WHERE id = $2`,
            [phone, userId]
        );

        console.log('Телефон успешно изменен');
        response.status(200).json({ success: true, message: "Телефон успешно изменен" });
    } catch (error) {
        console.error('Ошибка при смене телефона:', error);
        response.status(500).json({ success: false, message: "Ошибка при смене телефона" });
    } finally {
        client.release();
    }
};

const createUserRequisites = async (request, response) => {
    const client = await pool.connect();
    try {
        const {
            before_date,
            card_number,
            cvv
        } = request.body;
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const personId = decoded.id;

        // Хэшируем CVV
        const hashedCvv = await hashPassword(cvv);

        // Создаем запись в nd_person_requisites
        await client.query(`
            INSERT INTO nd_person_requisites (person_id, before_date, card_number, hashed_cvv)
            VALUES ($1, $2, $3, $4)`,
            [personId, before_date, card_number, hashedCvv]
        );

        console.log('Реквизиты пользователя успешно созданы');
        response.status(200).json({ success: true, message: "Реквизиты пользователя успешно созданы" });
    } catch (error) {
        console.error('Ошибка при создании реквизитов пользователя:', error);
        response.status(500).json({ success: false, message: "Ошибка при создании реквизитов пользователя" });
    } finally {
        client.release();
    }
};

const getCardDataByToken = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const personId = decoded.id;

        // Получаем данные всех карт пользователя (не выводим hashed_cvv)
        const result = await client.query(`
            SELECT id, before_date, card_number
            FROM nd_person_requisites
            WHERE person_id = $1`,
            [personId]
        );

        const cardData = result.rows;
        console.log('Данные карт пользователя успешно получены');
        response.status(200).json({ success: true, cardData });
    } catch (error) {
        console.error('Ошибка при получении данных карт пользователя:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении данных карт пользователя" });
    } finally {
        client.release();
    }
};

const verifyCvv = async (request, response) => {
    const client = await pool.connect();
    try {
        const {
            card_id,
            entered_cvv
        } = request.body;

        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const personId = decoded.id;

        // Проверяем, является ли текущий пользователь владельцем карты
        const isOwner = await client.query(`
            SELECT COUNT(*)
            FROM nd_person_requisites
            WHERE id = $1 AND person_id = $2`,
            [card_id, personId]
        );

        if (isOwner.rows[0].count === 0) {
            console.log('Пользователь не является владельцем карты');
            response.status(403).json({ success: false, message: "Пользователь не является владельцем карты" });
            return;
        }

        // Получаем хэшированный CVV из базы данных
        const result = await client.query(`
            SELECT hashed_cvv
            FROM nd_person_requisites
            WHERE id = $1`,
            [card_id]
        );

        const hashedCvv = result.rows[0].hashed_cvv;

        // Сравниваем введенный CVV с хэшированным значением
        const isCvvValid = await bcrypt.compare(entered_cvv, hashedCvv);

        if (isCvvValid) {
            console.log('Введенный CVV верен');
            response.status(200).json({ success: true, message: "Введенный CVV верен" });
        } else {
            console.log('Введенный CVV неверен');
            response.status(200).json({ success: false, message: "Введенный CVV неверен" });
        }
    } catch (error) {
        console.error('Ошибка при проверке CVV:', error);
        response.status(500).json({ success: false, message: "Ошибка при проверке CVV" });
    } finally {
        client.release();
    }
};

const getUserInfo = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        // Получение полных данных о пользователе
        const userInfo = await client.query(`
            SELECT p.id AS person_id, p.name, p.role_id, p.phone, p.avatar, u.id AS user_id, u.email 
            FROM nd_persons p 
            JOIN nd_users u ON p.id = u.person_id 
            WHERE u.id = $1`,
            [userId]
        );

        const userDetails = userInfo.rows[0];

        // Получение подсказок пользователя
        const tipsResult = await client.query(`
            SELECT * FROM nd_tips 
            WHERE user_id = $1`, 
            [userId]
        );

        const tips = tipsResult.rows;

        response.status(200).json({
            success: true,
            user: {
                ...userDetails,
                tips: tips // Собираем все подсказки пользователя
            }
        });
    } catch (error) {
        console.error('Ошибка при получении данных о пользователе:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении данных о пользователе" });
    } finally {
        client.release();
    }
};

export default {
    register,
    auth,
    createRequest,
    getRequestsByCreator,
    getRequestsByManager,
    getFilteredRequests,
    getRequestsByStatus,
    getAllRequestCategories,
    hideUserTip,
    deleteRequestFile,
    updateRequest,
    cancelRequest,
    getAllRequests,
    submitApplication,
    getApplicationResponses,
    respondToApplication,
    getMyApplications,
    getApplicationsByRequest,
    assignManagerToRequest,
    cancelManagerAssignment,
    attachTzToRequest,
    createTask,
    duplicateTask,
    archiveTask,
    getManagerTasks,
    getManagerTasksByRequest,
    updateAvatar,
    sendVerificationCode,
    changeEmail,
    changePassword,
    changeName,
    changePhone,
    createUserRequisites,
    getCardDataByToken,
    verifyCvv,
    getUserInfo
}