Описание проекта
Простое веб-приложение с бэкендом на Node.js/Express и фронтендом на React, реализующее аутентификацию пользователей с помощью JWT токенов.

## Функционал
Регистрация новых пользователей

Вход в систему

Доступ к защищенным ресурсам с JWT токеном

Хранение пользователей в памяти сервера

## Технологии
## Бэкенд
Node.js

Express

jsonwebtoken

cors

## Фронтенд
React

Fetch API для взаимодействия с бэкендом

## Установка и запуск
Требования
Node.js (версия 14 или выше)

npm или yarn

## Инструкции по запуску
1. Клонируйте репозиторий:

```bash git clone https://github.com/lilvodnik/app2.git cd app2```
2. Установите зависимости для бэкенда:

```bash cd backend
npm install```
3. Установите зависимости для фронтенда:

```bash
cd ../frontend
npm install```
4. Запустите бэкенд (из папки backend):

```bash
npm start```
5. Запустите фронтенд (из папки frontend):

```bash
npm start```
### Использование
Откройте http://localhost:3000 в браузере

Зарегистрируйте нового пользователя

Войдите в систему с вашими учетными данными

Получите доступ к защищенным данным после успешной аутентификации

### Структура проекта
app2/
├── backend/               # Бэкенд на Node.js/Express
│   ├── server.js          # Основной серверный файл
│   ├── package.json       # Зависимости бэкенда
│   └── ...                # Другие файлы бэкенда
├── frontend/              # Фронтенд на React
│   ├── public/            # Статические файлы
│   ├── src/               # Исходный код React
│   ├── package.json       # Зависимости фронтенда
│   └── ...                # Другие файлы фронтенда
└── README.md              # Этот файл
