# ---- build stage ----
FROM node:20-alpine AS build
WORKDIR /app

ARG VITE_OIDC_ISSUER=
ARG VITE_OIDC_CLIENT_ID=
ARG VITE_OIDC_REDIRECT_URI=
ARG VITE_OIDC_SCOPES=openid profile email
ENV VITE_OIDC_ISSUER=$VITE_OIDC_ISSUER
ENV VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID
ENV VITE_OIDC_REDIRECT_URI=$VITE_OIDC_REDIRECT_URI
ENV VITE_OIDC_SCOPES=$VITE_OIDC_SCOPES

COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json vite.config.ts tailwind.config.ts postcss.config.js index.html ./
COPY src ./src
RUN npm run build

# ---- runtime stage ----
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
