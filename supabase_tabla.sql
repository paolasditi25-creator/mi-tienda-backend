-- Pega esto en Supabase -> SQL Editor -> Run
-- Crea la tabla "usuarios" (el archivero de la frutería)

create table if not exists usuarios (
  id        bigint generated always as identity primary key,
  nombre    text not null,
  usuario   text not null unique,
  password  text not null,               -- se guarda ENCRIPTADA, nunca en texto normal
  rol       text not null default 'usuario' check (rol in ('admin', 'usuario')),
  creado    timestamptz not null default now()
);

-- Seguridad: nadie puede leer la tabla desde fuera,
-- solo nuestro backend (que usa la llave secreta).
alter table usuarios enable row level security;
