FROM node:22-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Create directory for SQLite database
RUN mkdir -p data

# Environment variables
ENV PORT=3000
ENV DB_PATH=/app/data/shorturl.db
ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "start"]
