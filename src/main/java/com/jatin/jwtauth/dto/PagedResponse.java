package com.jatin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * PagedResponse — generic pagination wrapper returned from pageable admin endpoints.
 *
 * @param <T> the element type
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PagedResponse<T> {
    /** The content items for the current page. */
    private List<T> content;
    /** Zero-based current page number. */
    private int page;
    /** Page size requested. */
    private int size;
    /** Total number of elements across all pages. */
    private long totalElements;
    /** Total number of pages. */
    private int totalPages;
    /** True if this is the last page. */
    private boolean last;
}
