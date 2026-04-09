FROM node:20-bullseye-slim

# Enable corepack to use pnpm
RUN corepack enable

WORKDIR /app

# Copy manifest and lockfile first for better caching
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy rest of source
COPY . .

# Build the project (client + server)
RUN pnpm build

EXPOSE 3000

CMD ["node", "dist/server/node-build.mjs"]
