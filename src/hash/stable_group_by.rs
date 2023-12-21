/// Implementation of `#![feature(slice_group_by)]` that works on stable
pub fn group_by<T, P: FnMut(&T, &T) -> bool>(slice: &[T], predicate: P) -> GroupBy<'_, T, P> {
    GroupBy { slice, predicate }
}

pub struct GroupBy<'a, T, P> {
    slice: &'a [T],
    predicate: P,
}

impl<'a, T: 'a, P> Iterator for GroupBy<'a, T, P>
where
    P: FnMut(&T, &T) -> bool,
{
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            None
        } else {
            let mut len = 1;
            let mut iter = self.slice.windows(2);
            while let Some([l, r]) = iter.next() {
                if (self.predicate)(l, r) {
                    len += 1
                } else {
                    break;
                }
            }
            let (head, tail) = self.slice.split_at(len);
            self.slice = tail;
            Some(head)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_group_by_example() {
        let slice = &[1, 1, 1, 3, 3, 2, 2, 2];

        let mut iter = group_by(slice, |a, b| a == b);

        assert_eq!(iter.next(), Some(&[1, 1, 1][..]));
        assert_eq!(iter.next(), Some(&[3, 3][..]));
        assert_eq!(iter.next(), Some(&[2, 2, 2][..]));
        assert_eq!(iter.next(), None);
    }
}
