FROM golang:1.24-alpine AS builder

# CGO va C kutubxonalarini o'rnatish
RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    musl-dev \
    libde265-dev \
    libheif-dev

# Ish katalogini yaratish
WORKDIR /app

# Go modullarini nusxalash va yuklab olish
COPY go.mod go.sum ./
RUN go mod download

# Barcha kodlarni nusxalash
COPY . .

# Binaryni qurish (CGO bilan)
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o main .

# Final stage - minimal image
FROM alpine:latest

# Kerakli runtime kutubxonalarini o'rnatish
RUN apk --no-cache add \
    ca-certificates \
    libde265 \
    libheif

# Ish katalogi
WORKDIR /root/

# Binary va kerakli kataloglarni nusxalash
COPY --from=builder /app/main .
COPY --from=builder /app/data ./data

# uploads katalogi uchun ruxsat
RUN mkdir -p /root/uploads

# Ma'lumotlar va rasmlar uchun volume
VOLUME ["/root/data", "/root/uploads"]

# Portni ochish
EXPOSE 1010

# Serverni ishga tushirish
CMD ["./main"]