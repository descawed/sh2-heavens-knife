use std::convert::From;

use nalgebra::{Matrix4, Vector3, Vector4};

pub type Mat4 = Matrix4<f32>;
pub type Vec4 = Vector4<f32>;
pub type Vec3 = Vector3<f32>;

pub fn get_mat_translation(m: &Mat4) -> Vec3 {
    Vec3::new(m.m14, m.m24, m.m34)
}

pub fn take_mat_translation(m: &mut Mat4) -> Vec3 {
    let translation = get_mat_translation(m);
    m.m14 = 0.0;
    m.m24 = 0.0;
    m.m34 = 0.0;
    m.m44 = 1.0;
    translation
}

pub fn get_transform(from: &Mat4, to: &Mat4) -> Mat4 {
    let Some(from_inverse) = from.try_inverse() else {
        log::warn!("Failed to invert from matrix {}", from);
        return Mat4::identity();
    };

    to * from_inverse
}

pub fn get_split_transform(from: &Mat4, to: &Mat4) -> (Mat4, Vec3) {
    let mut rotation = to.clone();
    let translation = take_mat_translation(&mut rotation);

    let mut parent_rotation = from.clone();
    let parent_translation = take_mat_translation(&mut parent_rotation);

    let relative_translation = translation - parent_translation;
    let inverse_parent_rotation = parent_rotation.try_inverse().unwrap_or_default();
    let relative_rotation = rotation * inverse_parent_rotation;

    (relative_rotation, relative_translation)
}

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

impl D3DXMATRIX {
    pub const fn new() -> Self {
        Self {
            _11: 0.0,
            _12: 0.0,
            _13: 0.0,
            _14: 0.0,
            _21: 0.0,
            _22: 0.0,
            _23: 0.0,
            _24: 0.0,
            _31: 0.0,
            _32: 0.0,
            _33: 0.0,
            _34: 0.0,
            _41: 0.0,
            _42: 0.0,
            _43: 0.0,
            _44: 0.0,
        }
    }

    pub const fn mat4(&self) -> Mat4 {
        Mat4::new(
            self._11, self._21, self._31, self._41,
            self._12, self._22, self._32, self._42,
            self._13, self._23, self._33, self._43,
            self._14, self._24, self._34, self._44,
        )
    }

    pub fn split_transforms(&self) -> (Mat4, Vec3) {
        let mut matrix = self.mat4();
        let translation = take_mat_translation(&mut matrix);

        (matrix, translation)
    }
}

impl Default for D3DXMATRIX {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Mat4> for D3DXMATRIX {
    fn from(value: Mat4) -> Self {
        Self {
            _11: value.m11,
            _12: value.m21,
            _13: value.m31,
            _14: value.m41,
            _21: value.m12,
            _22: value.m22,
            _23: value.m32,
            _24: value.m42,
            _31: value.m13,
            _32: value.m23,
            _33: value.m33,
            _34: value.m43,
            _41: value.m14,
            _42: value.m24,
            _43: value.m34,
            _44: value.m44,
        }
    }
}

impl From<&Mat4> for D3DXMATRIX {
    fn from(value: &Mat4) -> Self {
        Self {
            _11: value.m11,
            _12: value.m21,
            _13: value.m31,
            _14: value.m41,
            _21: value.m12,
            _22: value.m22,
            _23: value.m32,
            _24: value.m42,
            _31: value.m13,
            _32: value.m23,
            _33: value.m33,
            _34: value.m43,
            _41: value.m14,
            _42: value.m24,
            _43: value.m34,
            _44: value.m44,
        }
    }
}

impl From<D3DXMATRIX> for Mat4 {
    fn from(m: D3DXMATRIX) -> Self {
        m.mat4()
    }
}

impl From<&D3DXMATRIX> for Mat4 {
    fn from(m: &D3DXMATRIX) -> Self {
        m.mat4()
    }
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

impl D3DXVECTOR4 {
    pub const fn new() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 0.0,
        }
    }

    pub const fn vec4(&self) -> Vec4 {
        Vec4::new(self.x, self.y, self.z, self.w)
    }

    pub const fn vec3(&self) -> Vec3 {
        Vec3::new(self.x, self.y, self.z)
    }

    pub fn rotation_matrix(&self) -> Mat4 {
        Mat4::from_euler_angles(self.x, self.y, self.z)
    }
}

impl Default for D3DXVECTOR4 {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec4> for D3DXVECTOR4 {
    fn from(v: Vec4) -> Self {
        Self {
            x: v.x,
            y: v.y,
            z: v.z,
            w: v.w,
        }
    }
}

impl From<&Vec4> for D3DXVECTOR4 {
    fn from(v: &Vec4) -> Self {
        Self {
            x: v.x,
            y: v.y,
            z: v.z,
            w: v.w,
        }
    }
}

impl From<D3DXVECTOR4> for Vec4 {
    fn from(v: D3DXVECTOR4) -> Self {
        v.vec4()
    }
}

impl From<&D3DXVECTOR4> for Vec4 {
    fn from(v: &D3DXVECTOR4) -> Self {
        v.vec4()
    }
}

impl From<D3DXVECTOR4> for Vec3 {
    fn from(v: D3DXVECTOR4) -> Self {
        v.vec3()
    }
}

impl From<&D3DXVECTOR4> for Vec3 {
    fn from(v: &D3DXVECTOR4) -> Self {
        v.vec3()
    }
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

impl D3DXVECTOR3 {
    pub const fn new() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }
    }

    pub const fn vec3(&self) -> Vec3 {
        Vec3::new(self.x, self.y, self.z)
    }
}

impl Default for D3DXVECTOR3 {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec3> for D3DXVECTOR3 {
    fn from(v: Vec3) -> Self {
        Self {
            x: v.x,
            y: v.y,
            z: v.z,
        }
    }
}

impl From<&Vec3> for D3DXVECTOR3 {
    fn from(v: &Vec3) -> Self {
        Self {
            x: v.x,
            y: v.y,
            z: v.z,
        }
    }
}

impl From<D3DXVECTOR3> for Vec3 {
    fn from(v: D3DXVECTOR3) -> Self {
        v.vec3()
    }
}

impl From<&D3DXVECTOR3> for Vec3 {
    fn from(v: &D3DXVECTOR3) -> Self {
        v.vec3()
    }
}

impl std::fmt::Display for D3DXVECTOR3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:>10.4} {:>10.4} {:>10.4}]", self.x, self.y, self.z)
    }
}