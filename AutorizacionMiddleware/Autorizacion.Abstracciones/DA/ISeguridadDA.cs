﻿using Autorizacion.Abstracciones.Modelos;

namespace Autorizacion.Abstracciones.DA
{
    public interface ISeguridadDA
    {
        Task<Usuario> ObtenerUsuario(Usuario usuario);
        Task <IEnumerable<Perfil>> ObtenerPerfilesxUsuario(Usuario usuario);
    }
}
