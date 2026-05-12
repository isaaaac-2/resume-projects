# Sample Dockerfile — demonstrates container scanning in the pipeline.
# This intentionally uses a real base image so Trivy can detect CVEs.

FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency files first (layer caching)
COPY package*.json ./

# Install production dependencies only
RUN npm install --only=production

# Copy application source
COPY . .

# Run as non-root user (security best practice)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
