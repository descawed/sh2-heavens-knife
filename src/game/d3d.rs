#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXMATRIX {
    pub _11: f32,
    pub _12: f32,
    pub _13: f32,
    pub _14: f32,
    pub _21: f32,
    pub _22: f32,
    pub _23: f32,
    pub _24: f32,
    pub _31: f32,
    pub _32: f32,
    pub _33: f32,
    pub _34: f32,
    pub _41: f32,
    pub _42: f32,
    pub _43: f32,
    pub _44: f32,
}

impl std::fmt::Display for D3DXMATRIX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]",
            self._11, self._12, self._13, self._14, self._21, self._22, self._23, self._24, self._31,
            self._32, self._33, self._34, self._41, self._42, self._43, self._44
        )
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXVECTOR4 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}

impl std::fmt::Display for D3DXVECTOR4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]", self.x, self.y, self.z, self.w)
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXVECTOR3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl std::fmt::Display for D3DXVECTOR3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:>10.4} {:>10.4} {:>10.4}]", self.x, self.y, self.z)
    }
}